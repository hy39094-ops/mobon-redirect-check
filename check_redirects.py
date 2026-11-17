"""redirects.yaml 의 케이스대로 (구) 주소 → 신규 주소 리다이렉트를 검사한다.

사용:
  python check_redirects.py                          # yaml 의 base_url 사용
  python check_redirects.py --base-url https://stg.example.com
  python check_redirects.py --priority 1             # 1등급만
  BASE_URL=https://... python check_redirects.py

결과: 콘솔 표 + result.csv. 실패가 하나라도 있으면 종료 코드 1 (GitHub Actions 에서 실패로 표시).
"""
import argparse
import csv
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

UA = "Mozilla/5.0 (redirect-check)"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


NO_FOLLOW = urllib.request.build_opener(NoRedirect)


def first_hop(url):
    """리다이렉트를 따라가지 않고 (코드, Location) 반환."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        r = NO_FOLLOW.open(req, timeout=20)
        return r.status, ""
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "") or ""


def follow(url, max_hops=10):
    """리다이렉트를 끝까지 따라가 (최종 코드, 최종 URL, 거친 단계 수) 반환."""
    hops = 0
    while hops <= max_hops:
        code, loc = first_hop(url)
        if code in (301, 302, 303, 307, 308) and loc:
            url = urllib.parse.urljoin(url, loc)
            hops += 1
            continue
        return code, url, hops
    return "LOOP", url, hops


def path_q(url, base):
    """비교용: 같은 호스트면 '경로?쿼리' 만 남긴다."""
    if not url:
        return ""
    full = urllib.parse.urljoin(base + "/", url)
    p = urllib.parse.urlsplit(full)
    b = urllib.parse.urlsplit(base)
    if p.netloc and p.netloc != b.netloc:
        return full  # 다른 호스트로 가면 전체 주소로 비교
    return (p.path or "/") + (("?" + p.query) if p.query else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(Path(__file__).with_name("redirects.yaml")))
    ap.add_argument("--base-url")
    ap.add_argument("--priority", type=int, help="이 등급 이하만 실행 (1 이면 1등급만)")
    args = ap.parse_args()

    spec = yaml.safe_load(Path(args.file).read_text(encoding="utf-8"))
    d = spec.get("defaults", {})
    base = (args.base_url or os.environ.get("BASE_URL") or d["base_url"]).rstrip("/")
    final_status = d.get("final_status", 200)

    rows, fails = [], 0
    for c in spec["cases"]:
        if args.priority and c.get("priority", 1) > args.priority:
            continue
        url = base + c["from"]
        code, loc = first_hop(url)
        problems = []
        if code != c["status"]:
            problems.append(f"코드 {code} (기대 {c['status']})")
        if "to" in c and path_q(loc, base) != path_q(c["to"], base):
            problems.append(f"Location {loc or '(없음)'} (기대 {c['to']})")
        fcode, furl, hops = ("", "", 0)
        if "final" in c:
            fcode, furl, hops = follow(url)
            if path_q(furl, base) != path_q(c["final"], base) or fcode != final_status:
                problems.append(f"최종 {fcode} {path_q(furl, base)} (기대 {final_status} {c['final']})")
        ok = not problems
        fails += not ok
        rows.append({
            "result": "PASS" if ok else "FAIL",
            "priority": c.get("priority", 1),
            "name": c["name"],
            "from": c["from"],
            "status": code,
            "location": loc,
            "expected": f"{c['status']} {c.get('to', '')}".strip(),
            "final": f"{fcode} {path_q(furl, base)} ({hops}단계)" if "final" in c else "",
            "problem": "; ".join(problems),
            "note": c.get("note", ""),
        })
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] P{c.get('priority', 1)} {c['name']}: {c['from']} -> {code} {loc}" + ("" if ok else f"  !! {'; '.join(problems)}"))

    out = Path(__file__).with_name("result.csv")
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["result"])
        w.writeheader()
        w.writerows(rows)
    print(f"\nbase_url={base}  총 {len(rows)}건, 실패 {fails}건  -> {out}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
