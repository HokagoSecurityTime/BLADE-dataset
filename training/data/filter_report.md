# B 필터 결과

최종 2,027건 / 370 services / seed 42.

| signal_class | has_security | count |
| --- | --- | --- |
| owner | False | 169 |
| owner | True | 258 |
| tenant | False | 49 |
| tenant | True | 111 |
| both | False | 88 |
| both | True | 154 |
| path_only | False | 112 |
| path_only | True | 286 |
| none | False | 350 |
| none | True | 450 |

| method | count |
| --- | --- |
| DELETE | 84 |
| GET | 1304 |
| PATCH | 131 |
| POST | 290 |
| PUT | 218 |

none 쿼터: {'true': 450, 'false': 350}. 조정 시도: [{'quotas': {'true': 450, 'false': 350}, 'final_count': 2027}].

none service당 공유 상한 4에 도달: 121개. 전체 service당 최대 15건; 원본 상한 15건 도달 16개.

incomplete: 신호 그룹 원본 126건 → 최종 125건.

입력 전체 중복 키 초과분 24건 중 선택된 집합에서 16건 제거. 나머지는 앞선 제외/표본 선택에서 탈락했다.

규칙 순서: 신호 전량 유지 → none 저정보 제외 → true/false 순서의 무작위 추출(두 그룹 공유 service 상한 4) → incomplete 표시 → 선택된 레코드 중 입력 순서상 첫 endpoint 키 유지.

원본·A2 입력을 수정하지 않았으며 라벨링·학습·분할은 실행하지 않았다.
