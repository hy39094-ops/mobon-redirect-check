# mobon-redirect-check

모비온 홈페이지 주소 체계 변경 후, **(구) 주소로 들어왔을 때 신규 주소로 잘 이동하는지** 검사한다.

- `redirects.yaml`: 검사 케이스 (접속 주소, 기대 도착 주소, 등급). 테스트 시트의 주소 기준
- `check_redirects.py`: 케이스대로 접속해 리다이렉트를 끝까지 따라가고 결과를 `result.csv` 로 저장
- `.github/workflows/redirect-check.yml`: GitHub Actions 자동(15분) / 수동 실행

## 판정

리다이렉트를 끝까지 따라가 **도착한 페이지** 기준으로 판정한다.

| 결과 | 조건 |
|---|---|
| PASS | 정상 도착(2xx/3xx)하고 기대한 주소로 도착. 첫 응답이 200/301/302 어느 것이든 성공 |
| WARN | 정상 도착했지만 기대한 주소와 다른 곳에 도착 (예: http 로 접속했는데 https 로 안 바뀜) |
| FAIL | 도착 페이지가 4xx/5xx, 또는 접속 자체가 안 됨 (인증서 오류, 도메인 없음 등) |

FAIL 이 있으면 종료 코드 1 (Actions 에서 빨간 X).

## 실행

```bash
pip install -r requirements.txt
python check_redirects.py                                   # 테스트 서버 web-master.mobon.net
python check_redirects.py --base-url https://www.mobon.net  # 실서버 전환 후 같은 케이스로 검사
python check_redirects.py --priority 1                      # 1등급만
```

## 케이스 추가

```yaml
- { no: 10, name: 공지 목록, from: https://web-master.mobon.net/main/m2/support/notice_list.php, status: 301, to: /support/notice_list, final: https://web-master.mobon.net/support/notice_list, priority: 1 }
```

- `final`: 끝까지 따라갔을 때 도착해야 하는 주소. 전체 주소로 쓰면 http/https·호스트까지 비교
- `to`: 첫 이동 주소 (final 이 없을 때만 판정에 사용)
- `status`: 첫 응답 기대 코드 (기록용, 판정에는 쓰지 않음)
