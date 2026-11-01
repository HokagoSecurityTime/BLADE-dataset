# 후보 생성·분석 실행 기록 — 단계 A

사용자가 지정한 후보 JSONL은 실행 시작 시 없었고 `datasets/blade/raw/openapi-directory/APIs` 원본만 존재했다. 제공된 `sources/apisguru.py`를 실행해 후보를 생성했다. 원본 OpenAPI 파일은 수정하지 않았다.

추출기에서 보완한 부분:

- JSON Schema의 배열형 type(예: `[integer, null]`) 처리. null을 제외한 타입이 하나면 해당 타입, 복수 타입이면 기존 기본값에 맞춰 TEXT로 표현한다.
- OpenAPI 객체 키를 문자열 원문으로 보존. YAML의 on/off가 boolean이 되거나 응답 코드 200이 숫자가 되는 문제를 방지한다.
- C 기반 SafeLoader를 사용할 수 있으면 사용한다. 임의 객체를 구성하는 UnsafeLoader는 사용하지 않는다.
- service가 기존 상한 15건에 도달했으면 추가 명세를 파싱하기 전에 건너뛴다. 상한과 파일 탐색 순서는 유지한다.

처음 두 번의 추출 오류 및 재시도 로그는 apisguru_extraction*.log에 보존했다. Python 기반 로더 재시도는 실행 시간이 길어 해당 실행만 종료한 뒤 가속 로더로 다시 실행했다. 최종 성공 로그: `apisguru_extraction_keys.log`.

최종 결과: 명세 경로 4,138개, 후보 4,333건. 추출기 출력의 services=689는 defaultdict에 등록됐지만 후보를 내지 않은 service까지 포함한다. 분석 보고서의 **424개**는 실제 후보 JSONL에 존재하는 service만 집계한 값이다.

`python -m training.data.analyze_candidates` 실행 완료. raw SHA-256은 candidates_analysis.json에 기록했고 분석 전후 일치를 확인했다. 중복 키 제거는 분석·샘플링의 메모리상 계산이며 원본 후보 JSONL은 변경하지 않았다. processed 파일, 필터, 라벨링, 학습 또는 분할은 만들거나 실행하지 않았다.

검증: `python -m pytest -q` → **198 passed, 1 skipped, 3 warnings**. 후보 분석 및 추출기 회귀 테스트 6개 포함. 출력은 candidates_pytest.log에 보존했다.
