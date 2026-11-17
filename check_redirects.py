"""redirects.yaml 의 케이스대로 (구) 주소 → 신규 주소 리다이렉트를 검사한다.

사용:
  python check_redirects.py                                   # yaml 의 주소 그대로 (web-master.mobon.net)
  python check_redirects.py --base-url https://www.mobon.net  # 실서버 전환 후: 기본 호스트만 바꿔서 실행
  python check_redirects.py --priority 1                      # 1등급만

판정 (리다이렉트를 끝까지 따라가서 도착한 페이지 기준):
  FAIL : 도착 페이지가 4xx/5xx 이거나 접속 자체가 안 됨 (인증서 오류, DNS 오류 등)
  WARN : 정상 도착(2xx/3xx)했지만 기대한 주소(to/final)와 다른 곳에 도착함
  PASS : 정상 도착했고 기대한 주소로 도착함 (첫 응답이 200/301/302 어느 것이든 성공)
  첫 응답 코드(status)는 기록만 하고 판정에는 쓰지 않는다.

주소 비교:
  to / final 이 '/경로' 처럼 상대 주소면 → 경로+쿼리만 비교
  to / final 이 'https://...' 처럼 전체 주소면 → 프로토콜·호스트까지 전부 비교 (http→https 전환 확인용)

결과: 콘솔 + result.csv. FAIL 이 하나라도 있으면 종료 코드 1 (WARN 만 있으면 0).
"""
import argparse
import csv
import sys
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


def first_hop(url):
    """리다이렉트를 따라가지 않고 (코드, Location) 반환. 접속 실패는 ('ERR 이유', '')."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        r = NO_FOLLOW.open(req, timeout=20)
        return r.status, ""
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "") or ""
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "CERTIFICATE_VERIFY_FAILED" in reason:
            return "ERR 인증서 오류(" + ("호스트 불일치" if "Hostname mismatch" in reason else "검증 실패") + ")", ""
        if "getaddrinfo" in reason or "Name or service" in reason:
            return "ERR 도메인 못 찾음", ""
        return f"ERR {reason[:60]}", ""
    except Exception as e:  # noqa: BLE001
        return f"ERR {type(e).__name__}", ""


def follow(url, max_hops=10):
    """리다이렉트를 끝까지 따라가 (최종 코드, 최종 URL, 이동 경로 문자열) 반환."""
    steps = []
    for _ in range(max_hops):
        code, loc = first_hop(url)
        steps.append(str(code))
        if code in REDIRECT and loc:
            url = urllib.parse.urljoin(url, loc)
            continue
        return code, url, " → ".join(steps)
    return "LOOP", url, " → ".join(steps)


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

    rows = []
    count = {"PASS": 0, "WARN": 0, "FAIL": 0}
    for c in spec["cases"]:
        if args.priority and c.get("priority", 1) > args.priority:
            continue
        frm = swap(c["from"])
        url = frm if frm.startswith(("http://", "https://")) else new_base + frm
        to = swap(c["to"]) if "to" in c else None
        final = swap(c["final"]) if "final" in c else None

        code, loc = first_hop(url)
        fcode, furl, path = follow(url)

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
        count[result] += 1

        rows.append({
            "result": result,
            "no": c.get("no", ""),
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
        tag = f"#{c['no']} " if c.get("no") else ""
        print(f"[{result}] P{c.get('priority', 1)} {tag}{c['name']}: {path}  {furl}"
              + ("" if result == "PASS" else f"\n        !! {'; '.join(problems)}"))

    out = Path(__file__).with_name("result.csv")
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["result"])
        w.writeheader()
        w.writerows(rows)
    print(f"\n대상 {new_base}  총 {len(rows)}건  PASS {count['PASS']} / WARN {count['WARN']} / FAIL {count['FAIL']}  -> {out}")
    sys.exit(1 if count["FAIL"] else 0)


if __name__ == "__main__":
    main()
