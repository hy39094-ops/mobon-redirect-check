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
        "| No. | 등급 | 접속 주소 (Test step) | 기대 결과 (이동할 주소) | 응답 코드 흐름 | 실제 도착 주소 | 기대 주소로 이동 | 결과 | 비고 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        moved = "-" if not r["expected"] else ("O" if r["result"] == "PASS" else "X")
        note = "; ".join(x for x in (r["problem"], r["note"]) if x)
        lines.append("| " + " | ".join(md(x) for x in (
            r["no"], r["priority"], r["from"], r["expected"] or "(정상 응답)", r["path"],
            r["final_url"], moved, icon[r["result"]], note,
        )) + " |")
    lines += ["", "응답 코드 흐름 예: `301 → /support/notice_list → 200` = 처음 301 로 /support/notice_list 로 이동했고, 거기서 200 응답"]
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
