"""redirects.yaml 의 케이스대로 (구) 주소 → 신규 주소 리다이렉트를 검사한다.

사용:
  python check_redirects.py                                   # yaml 의 주소 그대로 (web-master.mobon.net)
  python check_redirects.py --base-url https://www.mobon.net  # 실서버 전환 후: 기본 호스트만 바꿔서 실행
  python check_redirects.py --priority 1                      # 1등급만

판정 (리다이렉트를 끝까지 따라가서 도착한 페이지 기준):
  FAIL : 도착 페이지가 4xx/5xx 이거나 접속 자체가 안 됨 (DNS 오류, 타임아웃 등)
  참고 : 정상 도착했지만 기대한 주소와 다른 곳에 도착했거나 인증서 경고가 있으면 PASS 로 두고
         '이동' 칸을 X 로, 사유·참고 칸에 내용을 적는다 (인증서 검사 없이 이동은 끝까지 확인한다)
  PASS : 정상 도착했고 기대한 주소로 도착함 (첫 응답이 200/301/302 어느 것이든 성공)
  첫 응답 코드(status)는 기록만 하고 판정에는 쓰지 않는다.

주소 비교:
  to / final 이 '/경로' 처럼 상대 주소면 → 경로+쿼리만 비교
  to / final 이 'https://...' 처럼 전체 주소면 → 프로토콜·호스트까지 전부 비교 (http→https 전환 확인용)

결과: 콘솔 + result.csv. FAIL 이 하나라도 있으면 종료 코드 1.
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

# 인증서 오류가 난 호스트 → 이유. 브라우저라면 경고가 뜨는 곳이라 참고 칸에 적는다.
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


def split_url(url, width=WRAP):
    """긴 주소를 / ? & 같은 끊기 좋은 자리에서 여러 줄로 나눈다."""
    url = str(url)
    if len(url) <= width:
        return [url]
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
    return lines


def wrap_url(url, width=WRAP):
    """마크다운 표 칸용: 주소 전체를 링크 하나로 두고, 보이는 글자만 줄바꿈한다.
    (줄마다 따로 쓰면 GitHub 가 첫 줄만 링크로 만들어 주소가 끊겨 보인다)"""
    url = str(url)
    if not url.startswith(("http://", "https://")):
        return "<br>".join(md(x) for x in split_url(url, width))
    text = "<br>".join(md(x).replace("[", "\\[").replace("]", "\\]") for x in split_url(url, width))
    href = url.replace(" ", "%20").replace("(", "%28").replace(")", "%29").replace("|", "%7C")
    return f"[{text}]({href})"


def short_codes(codes):
    """'301 → 200' 처럼 숫자만 남긴다. 접속 오류 같은 긴 문구는 'ERR' 로 줄인다."""
    return " → ".join("ERR" if str(c).startswith("ERR") else str(c) for c in str(codes).split(" → "))


def write_report(rows, count, target, started):
    """시트 형태의 결과 문서(report.md)를 만들고, GitHub Actions 에서는 실행 화면 Summary 에도 붙인다."""
    icon = {"PASS": "✅ PASS", "FAIL": "❌ FAIL"}
    lines = [
        "# 리다이렉트 검사 결과",
        "",
        f"- 실행 시각: {started} (KST)",
        f"- 대상: `{target}`",
        f"- 결과: **PASS {count['PASS']} / FAIL {count['FAIL']}** (총 {len(rows)}건)",
        "- 판정: 도착 페이지가 정상(200·301·302 등)이면 PASS, 4xx·5xx·접속 오류면 FAIL. 이동 = 기대 주소로 갔는지(O/X)",
        "",
        "| 결과 | No. | 접속 주소 | 기대 결과 | 응답 코드 | 실제 도착 주소 | 이동 |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        moved = r["moved"]
        lines.append("| " + " | ".join((
            icon[r["result"]],
            md(r["no"]),
            wrap_url(r["from"]),
            wrap_url(r["expected"]) if r["expected"] else "(정상 응답)",
            md(short_codes(r["codes"])),
            wrap_url(r["final_url"]),
            moved,
        )) + " |")

    issues = [r for r in rows if r["problem"]]
    if issues:
        lines += ["", "## 확인 필요 (FAIL 사유 · 참고)", ""]
        for r in issues:
            head = f"No.{r['no']} " if r["no"] else ""
            label = "FAIL" if r["result"] == "FAIL" else "참고"
            lines.append(f"- **{label}** {head}{md(r['name'])}: {md(r['problem'])}")
    lines += ["", "응답 코드 예: `301 → 200` = 처음 301 로 이동한 뒤 도착 페이지에서 200"]
    text = "\n".join(lines) + "\n"
    out = Path(__file__).with_name("report.md")
    out.write_text(text, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text)
    return out


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
    count = {"PASS": 0, "FAIL": 0}
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

        # 판정: 도착 페이지가 정상(2xx/3xx)이면 PASS, 4xx/5xx·접속 오류면 FAIL.
        # 기대 주소와 다른 곳에 도착했거나 인증서 경고가 있으면 PASS 로 두고 '참고'에만 적는다.
        problems = []
        moved_ok = None  # 기대 주소가 있을 때 그 주소로 갔는지 (O/X 표시용)
        if not isinstance(fcode, int) or fcode >= 400:
            result = "FAIL"
            problems.append(f"도착 실패: {fcode}")
        else:
            result = "PASS"
        if final is not None:
            moved_ok = same(furl, final)
            if result == "PASS" and not moved_ok:
                problems.append(f"기대와 다른 주소에 도착 (기대 {final})")
        elif to is not None:
            loc_abs = urllib.parse.urljoin(url, loc) if loc else url
            moved_ok = same(loc_abs, to)
            if result == "PASS" and not moved_ok:
                problems.append(f"이동 주소 {loc or '(이동 없음)'} (기대 {to})")
        for host, why in CERT_ISSUES.items():
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
            "moved": "-" if moved_ok is None else ("O" if moved_ok else "X"),
            "problem": "; ".join(problems),
            "note": c.get("note", ""),
        })
        tag = f"#{c['sheet_no']} " if c.get("sheet_no") else ""
        print(f"[{result}] P{c.get('priority', 1)} {tag}{c['name']}: {codes}  {furl}"
              + (f"\n        {'!!' if result == 'FAIL' else '참고'} {'; '.join(problems)}" if problems else ""))

    out = Path(__file__).with_name("result.csv")
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["result"])
        w.writeheader()
        w.writerows(rows)
    report = write_report(rows, count, new_base, started)
    print(f"\n대상 {new_base}  총 {len(rows)}건  PASS {count['PASS']} / FAIL {count['FAIL']}  -> {out}, {report}")
    sys.exit(1 if count["FAIL"] else 0)


if __name__ == "__main__":
    main()
