"""redirects.yaml 의 케이스대로 (구) 주소 → 신규 주소 리다이렉트를 검사한다.

사용:
  python check_redirects.py                                   # yaml 의 주소 그대로 (web-master.mobon.net)
  python check_redirects.py --base-url https://www.mobon.net  # 실서버 전환 후: 기본 호스트만 바꿔서 실행
  python check_redirects.py --priority 1                      # 1등급만

판정 (리다이렉트를 끝까지 따라가서 도착한 페이지 기준):
  FAIL : 도착 페이지가 4xx/5xx 이거나 접속 자체가 안 됨 (DNS 오류, 타임아웃 등)
  WARN : 정상 도착(2xx/3xx)했지만 기대한 주소(to/final)와 다른 곳에 도착함,
         또는 중간에 인증서 오류가 있음 (인증서 검사 없이 이동은 끝까지 확인한다)
  PASS : 정상 도착했고 기대한 주소로 도착함 (첫 응답이 200/301/302 어느 것이든 성공)
  첫 응답 코드(status)는 기록만 하고 판정에는 쓰지 않는다.

주소 비교:
  to / final 이 '/경로' 처럼 상대 주소면 → 경로+쿼리만 비교
  to / final 이 'https://...' 처럼 전체 주소면 → 프로토콜·호스트까지 전부 비교 (http→https 전환 확인용)

결과: 콘솔 + result.csv. FAIL 이 하나라도 있으면 종료 코드 1 (WARN 만 있으면 0).
"""
import argparse
import csv
import os
import ssl
import sys
from datetime import datetime, timedelta, timezone
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

UA = "Mozilla/5.0 (redirect-check)"
REDIRECT = (301, 302, 303, 307, 308)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


NO_FOLLOW = urllib.request.build_opener(NoRedirect)
_insecure_ctx = ssl.create_default_context()
_insecure_ctx.check_hostname = False
_insecure_ctx.verify_mode = ssl.CERT_NONE
NO_FOLLOW_INSECURE = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=_insecure_ctx))

# 인증서 오류가 난 호스트 → 이유. 브라우저라면 경고가 뜨는 곳이라 WARN 으로 표시한다.
CERT_ISSUES = {}


def first_hop(url):
    """리다이렉트를 따라가지 않고 (코드, Location) 반환. 접속 실패는 ('ERR 이유', '').
    인증서 오류는 기록해 두고, 인증서 검사 없이 다시 요청해서 이동은 계속 확인한다."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    for opener in (NO_FOLLOW, NO_FOLLOW_INSECURE):
        try:
            r = opener.open(req, timeout=20)
            return r.status, ""
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location", "") or ""
        except urllib.error.URLError as e:
            reason = str(e.reason)
            if "CERTIFICATE_VERIFY_FAILED" in reason and opener is NO_FOLLOW:
                host = urllib.parse.urlsplit(url).hostname
                CERT_ISSUES[host] = "인증서 오류(" + ("이 주소용 인증서 아님" if "Hostname mismatch" in reason else "검증 실패") + ")"
                continue
            if "getaddrinfo" in reason or "Name or service" in reason:
                return "ERR 도메인 못 찾음", ""
            return f"ERR {reason[:60]}", ""
        except Exception as e:  # noqa: BLE001
            return f"ERR {type(e).__name__}", ""
    return "ERR 접속 실패", ""


def follow(url, max_hops=10):
    """리다이렉트를 끝까지 따라가 (최종 코드, 최종 URL, 코드 경로, 상세 경로) 반환.
    코드 경로 예: '301 → 200' / 상세 경로 예: '301 → /support/notice_list → 200'"""
    codes, detail = [], []
    for _ in range(max_hops):
        code, loc = first_hop(url)
        codes.append(str(code))
        detail.append(str(code))
        if code in REDIRECT and loc:
            detail.append(loc)
            url = urllib.parse.urljoin(url, loc)
            continue
        return code, url, " → ".join(codes), " → ".join(detail)
    return "LOOP", url, " → ".join(codes), " → ".join(detail)


def md(s):
    """마크다운 표 칸에 넣을 수 있게 | 와 줄바꿈을 정리."""
    return str(s).replace("|", "\\|").replace("\n", " ")


WRAP = 48  # 주소 칸 한 줄 최대 글자 수


def wrap_url(url, width=WRAP):
    """긴 주소를 / ? & 같은 끊기 좋은 자리에서 줄바꿈(<br>)한다. 표 한 칸에 다 보이게 하려는 용도."""
    url = str(url)
    if len(url) <= width:
        return md(url)
    lines, cur = [], ""
    i = 0
    while i < len(url):
        # 다음 끊는 자리까지의 조각
        j = i + 1
        while j < len(url) and url[j] not in "/?&":
            j += 1
        piece = url[i:j]
        if cur and len(cur) + len(piece) > width:
            lines.append(cur)
            cur = ""
        while len(piece) > width:  # 끊을 자리 없이 너무 긴 조각은 강제로 자른다
            lines.append(cur + piece[: width - len(cur)])
            piece = piece[width - len(cur):]
            cur = ""
        cur += piece
        i = j
    if cur:
        lines.append(cur)
    return "<br>".join(md(x) for x in lines)


def short_codes(codes):
    """'301 → 200' 처럼 숫자만 남긴다. 접속 오류 같은 긴 문구는 'ERR' 로 줄인다."""
    return " → ".join("ERR" if str(c).startswith("ERR") else str(c) for c in str(codes).split(" → "))


def write_report(rows, count, target, started):
    """시트 형태의 결과 문서(report.md)를 만들고, GitHub Actions 에서는 실행 화면 Summary 에도 붙인다."""
    icon = {"PASS": "✅ PASS", "WARN": "⚠️ WARN", "FAIL": "❌ FAIL"}
    lines = [
        "# 리다이렉트 검사 결과",
        "",
        f"- 실행 시각: {started} (KST)",
        f"- 대상: `{target}`",
        f"- 결과: **PASS {count['PASS']} / WARN {count['WARN']} / FAIL {count['FAIL']}** (총 {len(rows)}건)",
        "- 판정: 도착 페이지가 4xx·5xx·접속 오류면 FAIL, 정상 도착했지만 기대 주소와 다르면 WARN",
        "",
        "| 결과 | No. | 접속 주소 | 기대 결과 | 응답 코드 | 실제 도착 주소 | 이동 |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        moved = "-" if not r["expected"] else ("O" if r["result"] == "PASS" else "X")
        lines.append("| " + " | ".join((
            icon[r["result"]],
            md(r["no"]),
            wrap_url(r["from"]),
            wrap_url(r["expected"]) if r["expected"] else "(정상 응답)",
            md(short_codes(r["codes"])),
            wrap_url(r["final_url"]),
            moved,
        )) + " |")

    issues = [r for r in rows if r["result"] != "PASS"]
    if issues:
        lines += ["", "## 확인 필요 (WARN / FAIL 사유)", ""]
        for r in issues:
            head = f"No.{r['no']} " if r["no"] else ""
            lines.append(f"- **{r['result']}** {head}{md(r['name'])}: {md(r['problem'])}")
    lines += ["", "응답 코드 예: `301 → 200` = 처음 301 로 이동한 뒤 도착 페이지에서 200"]
    pages = os.environ.get("REPORT_PAGE_URL")
    if pages:
        lines.insert(2, f"- 📄 **[스티키 헤더 결과 페이지 보기]({pages})** (표가 길 때는 이 페이지가 보기 편함)")
    text = "\n".join(lines) + "\n"
    out = Path(__file__).with_name("report.md")
    out.write_text(text, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text)
    write_html(rows, count, target, started)
    return out


def write_html(rows, count, target, started):
    """같은 결과를 스티키 헤더가 있는 HTML 페이지(site/index.html)로 만든다. GitHub Pages 로 올리는 용도."""
    from html import escape as e

    def url_cell(u):
        return wrap_url(u).replace("\\|", "|") if u else ""

    trs = []
    for r in rows:
        moved = "-" if not r["expected"] else ("O" if r["result"] == "PASS" else "X")
        reason = escape_attr = e(r["problem"]) if r["result"] != "PASS" else ""
        trs.append(
            f'<tr class="{r["result"].lower()}">'
            f'<td><span class="badge {r["result"].lower()}">{r["result"]}</span></td>'
            f'<td class="num">{e(str(r["no"]))}</td>'
            f'<td class="url">{url_cell(r["from"])}</td>'
            f'<td class="url">{url_cell(r["expected"]) or "(정상 응답)"}</td>'
            f'<td class="code">{e(short_codes(r["codes"]))}</td>'
            f'<td class="url">{url_cell(r["final_url"])}</td>'
            f'<td class="num">{moved}</td>'
            f'<td class="reason">{reason}</td></tr>'
        )
    html = f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>리다이렉트 검사 결과</title>
<style>
:root {{ --bg:#f7f8fa; --card:#fff; --fg:#1d2330; --muted:#5b6475; --line:#dde1e8; --head:#eef1f6;
  --pass:#1f7a45; --pass-bg:#e2f5e9; --warn:#8a5a00; --warn-bg:#fff1cc; --fail:#b42318; --fail-bg:#fde2df; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#14171c; --card:#1c2027; --fg:#e6e9ef; --muted:#9aa3b2; --line:#2e343e; --head:#252a33;
  --pass:#7fd6a0; --pass-bg:#1d3527; --warn:#f0c869; --warn-bg:#3a3017; --fail:#ff8f85; --fail-bg:#3d1f1c; }} }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 system-ui,-apple-system,"Malgun Gothic",sans-serif; }}
header {{ padding:20px max(16px,2vw) 12px; }}
h1 {{ font-size:20px; margin:0 0 6px }}
.meta {{ color:var(--muted); display:flex; flex-wrap:wrap; gap:6px 18px }}
.meta b {{ color:var(--fg) }}
.filters {{ display:flex; gap:6px; margin-top:10px; flex-wrap:wrap }}
.filters button {{ font:inherit; border:1px solid var(--line); background:var(--card); color:var(--fg); border-radius:999px; padding:3px 12px; cursor:pointer }}
.filters button[aria-pressed="true"] {{ background:var(--fg); color:var(--card) }}
.wrap {{ padding:0 max(16px,2vw) 32px; }}
table {{ width:100%; border-collapse:separate; border-spacing:0; background:var(--card); border:1px solid var(--line); border-radius:8px }}
thead th {{ position:sticky; top:0; z-index:2; background:var(--head); text-align:left; font-weight:600; padding:10px; border-bottom:1px solid var(--line); white-space:nowrap }}
td {{ padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top }}
tr:last-child td {{ border-bottom:0 }}
td.url {{ font-family:ui-monospace,Consolas,monospace; font-size:12.5px; word-break:break-all; min-width:220px }}
td.code {{ white-space:nowrap; font-variant-numeric:tabular-nums }}
td.num {{ text-align:center; white-space:nowrap }}
td.reason {{ color:var(--muted); font-size:12.5px; min-width:180px }}
.badge {{ font-weight:700; font-size:12px; padding:2px 8px; border-radius:999px; white-space:nowrap }}
.badge.pass {{ color:var(--pass); background:var(--pass-bg) }}
.badge.warn {{ color:var(--warn); background:var(--warn-bg) }}
.badge.fail {{ color:var(--fail); background:var(--fail-bg) }}
.scroll {{ }}  /* 가로 스크롤 상자를 두면 스티키 헤더가 페이지 스크롤을 따라오지 않아 비워 둔다. 주소는 줄바꿈으로 칸 안에 들어간다 */
</style></head><body>
<header>
  <h1>리다이렉트 검사 결과</h1>
  <div class="meta">
    <span>실행 <b>{e(started)}</b> (KST)</span>
    <span>대상 <b>{e(target)}</b></span>
    <span>PASS <b>{count['PASS']}</b> · WARN <b>{count['WARN']}</b> · FAIL <b>{count['FAIL']}</b> / 총 {len(rows)}건</span>
  </div>
  <div class="filters" role="group" aria-label="결과 필터">
    <button data-f="all" aria-pressed="true">전체</button>
    <button data-f="fail" aria-pressed="false">FAIL</button>
    <button data-f="warn" aria-pressed="false">WARN</button>
    <button data-f="pass" aria-pressed="false">PASS</button>
  </div>
</header>
<div class="wrap"><div class="scroll"><table>
<thead><tr><th>결과</th><th>No.</th><th>접속 주소</th><th>기대 결과</th><th>응답 코드</th><th>실제 도착 주소</th><th>이동</th><th>사유</th></tr></thead>
<tbody>
{chr(10).join(trs)}
</tbody></table></div>
<p class="meta">판정: 도착 페이지가 4xx·5xx·접속 오류면 FAIL, 정상 도착했지만 기대 주소와 다르면 WARN. 응답 코드 예: 301 → 200</p>
</div>
<script>
document.querySelectorAll('.filters button').forEach(b => b.addEventListener('click', () => {{
  document.querySelectorAll('.filters button').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
  const f = b.dataset.f;
  document.querySelectorAll('tbody tr').forEach(tr => {{ tr.hidden = f !== 'all' && !tr.classList.contains(f); }});
}}));
</script>
</body></html>
"""
    site = Path(__file__).with_name("site")
    site.mkdir(exist_ok=True)
    (site / "index.html").write_text(html, encoding="utf-8")


def same(actual_abs, expected):
    """expected 가 전체 주소면 전체 비교, 상대 주소면 경로+쿼리만 비교."""
    a = urllib.parse.urlsplit(actual_abs)
    if expected.startswith(("http://", "https://")):
        e = urllib.parse.urlsplit(expected)
        return (a.scheme, a.netloc, a.path or "/", a.query) == (e.scheme, e.netloc, e.path or "/", e.query)
    e = urllib.parse.urlsplit(expected)
    return (a.path or "/", a.query) == (e.path or "/", e.query)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(Path(__file__).with_name("redirects.yaml")))
    ap.add_argument("--base-url", help="yaml 의 기본 호스트(defaults.base_url)를 이 주소로 바꿔서 실행")
    ap.add_argument("--priority", type=int, help="이 등급 이하만 실행 (1 이면 1등급만)")
    args = ap.parse_args()

    spec = yaml.safe_load(Path(args.file).read_text(encoding="utf-8"))
    d = spec.get("defaults", {})
    base = d["base_url"].rstrip("/")
    new_base = (args.base_url or base).rstrip("/")
    final_status = d.get("final_status", 200)

    def swap(s):
        s = str(s)
        return new_base + s[len(base):] if s.startswith(base) else s

    started = datetime.now(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    count = {"PASS": 0, "WARN": 0, "FAIL": 0}
    for c in spec["cases"]:
        if args.priority and c.get("priority", 1) > args.priority:
            continue
        frm = swap(c["from"])
        url = frm if frm.startswith(("http://", "https://")) else new_base + frm
        to = swap(c["to"]) if "to" in c else None
        final = swap(c["final"]) if "final" in c else None

        CERT_ISSUES.clear()
        code, loc = first_hop(url)
        fcode, furl, codes, path = follow(url)

        problems = []
        if not isinstance(fcode, int) or fcode >= 400:
            result = "FAIL"
            problems.append(f"도착 실패: {fcode}")
        else:
            result = "PASS"
            if final is not None and not same(furl, final):
                result = "WARN"
                problems.append(f"도착 주소 {furl} (기대 {final})")
            elif final is None and to is not None:
                loc_abs = urllib.parse.urljoin(url, loc) if loc else url
                if not same(loc_abs, to):
                    result = "WARN"
                    problems.append(f"이동 주소 {loc or '(이동 없음)'} (기대 {to})")
        for host, why in CERT_ISSUES.items():
            if result == "PASS":
                result = "WARN"
            problems.append(f"{host}: {why}, 브라우저 경고 발생")
        count[result] += 1

        rows.append({
            "result": result,
            "no": c.get("sheet_no", ""),
            "priority": c.get("priority", 1),
            "name": c["name"],
            "from": url,
            "first_status": code,
            "location": loc,
            "final_status": fcode,
            "final_url": furl,
            "codes": codes,
            "path": path,
            "expected": final or to or "",
            "problem": "; ".join(problems),
            "note": c.get("note", ""),
        })
        tag = f"#{c['sheet_no']} " if c.get("sheet_no") else ""
        print(f"[{result}] P{c.get('priority', 1)} {tag}{c['name']}: {codes}  {furl}"
              + ("" if result == "PASS" else f"\n        !! {'; '.join(problems)}"))

    out = Path(__file__).with_name("result.csv")
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["result"])
        w.writeheader()
        w.writerows(rows)
    report = write_report(rows, count, new_base, started)
    print(f"\n대상 {new_base}  총 {len(rows)}건  PASS {count['PASS']} / WARN {count['WARN']} / FAIL {count['FAIL']}  -> {out}, {report}")
    sys.exit(1 if count["FAIL"] else 0)


if __name__ == "__main__":
    main()
