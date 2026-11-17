# mobon-redirect-check

모비온 홈페이지 주소 체계 변경 후, **(구) 주소로 들어왔을 때 신규 주소로 301/302 리다이렉트되는지** 검사한다.

- `redirects.yaml`: 검사 케이스 (구 주소, 기대 코드, 기대 이동 주소, 등급)
- `check_redirects.py`: yaml 을 읽어 실제로 요청하고 결과를 `result.csv` 로 저장
- `.github/workflows/redirect-check.yml`: GitHub Actions 에서 수동 실행

## 로컬 실행

```bash
pip install -r requirements.txt
python check_redirects.py --base-url https://www.mobon.net
python check_redirects.py --base-url https://www.mobon.net --priority 1   # 1등급만
```

실패가 있으면 종료 코드 1.

## 케이스 추가

`redirects.yaml` 의 `cases` 에 한 줄 추가:

```yaml
- { name: 공지 상세, from: "/main/m2/support/notice_view.php?no=921", status: 301, to: "/support/notice_view?no=921", priority: 1 }
```

`final:` 을 넣으면 리다이렉트를 끝까지 따라가 최종 도착 주소와 200 여부도 확인한다.

## 규칙

| (구) 주소 | 신규 주소 | 응답 |
|---|---|---|
| `/main/m2`, `/main/m2/`, `/main/m2/index.php` | `/` | 301 |
| `/main/m2/{경로}.php` | `/{경로}` | 301 |
| `/bridge/{폴더}/index.php` | `/bridge/{폴더}` | 301 |
| `/v2/external/{site}/index.php` | `/v2/external/{site}` | 301 |

쿼리 문자열은 그대로 유지된다.
