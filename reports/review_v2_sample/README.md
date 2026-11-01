# data-v2 검수 샘플 (시트 생성만, 라벨 변경 없음) — 2026-10-23

data-v1 해시 assert 통과(시작·종료): train_v30.jsonl a99d30da2d29907e…, val_v30.jsonl 62bdadb29cae7aaf…, test_v30.jsonl 9bd47216575afc60…, policy_label_v3.0.1.md d0913c27b5de185e…. 입력: datasets/blade/processed/train_v2_draft.jsonl(Gitea 371건), test_v30.jsonl(읽기 전용). seed 42.

## 시트 A — Gitea 코드 있음 ∧ manual ∧ (가) 정보 부족 사유: 30건
- 모집단 80건(Gitea manual 중 override 아님 ∧ 사유 분류 (가)). 사유 분류는 scripts/audit_data_v1.py의 manual_reason(모델 rationale 정규식) 기준.
- 층별 모집단 / 추출: 관계 미확인 23 / 9, 인증만 확인 53 / 18, 접근 조건 미명시 4 / 3, 기타 0 / 0. 층당 최소 3건, 비율 배분 후 30건으로 조정.
- 목적: 코드를 보면 구체 label이 정해지는데 보수적으로 manual이 붙었는지 확인.

## 시트 B — visibility_dependent override 96건 중 10건
- 모집단 96건(모델 label과 무관하게 manual override). 추출 10건.
- 대조: test_v30에서 핸들러 코드에 패턴 `visib|private|is_public|public\b|hidden|publish|restricted|anonymous`이 있는 건 52건(test_visibility_refs 시트/CSV). 정답 분포: {'role_required': 4, 'owner_match': 33, 'public': 15}. 같은 유형을 test가 어떻게 채점하는지 참고.

## 시트 C — Gitea declared ∧ public 12건 전체
- 모집단 = 추출 12건. 코드 기준 public이 맞는지 확인(맞으면 override 없이 public 유지 예정).

## 공통 열
id, source, method, path, security_state, 핸들러 코드(전체), OAS operation 발췌, 현재 label, label_before_override, 사유 분류, 모델 rationale 원문, reviewer_label(빈칸, 7종 label), reviewer_confidence(high/mid/low), reviewer_note. reviewer_* 열은 노란색.

## 검수 후 집계 지표
- 시트 A: reviewer_label이 구체 label(6종)인 비율 = 과보류율 추정치. 이 비율로 manual 쿼터·재라벨 방침(A/B)을 결정한다. 층별로도 산출.
- 시트 B: reviewer_label이 manual인 비율(override 유지 타당성)과 구체 label로 바뀐 건의 label 분포; test_visibility_refs의 정답 분포와 대조.
- 시트 C: reviewer_label == public 비율. 전부 public이면 Gitea에 security_declared_public override를 적용하지 않는다.
- 세 시트 모두 reviewer_confidence=low 건은 2차 검수 대상으로 분리.

파일: review_sheet.xlsx(시트 4개), sheet_A.csv, sheet_B.csv, sheet_C.csv, test_visibility_refs.csv. 스크립트 scripts/build_review_v2_sample.py.
