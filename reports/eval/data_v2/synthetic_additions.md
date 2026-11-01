# data-v2 합성 보강(3-1): 취약 변형 + 프레임워크 다양화 서비스 (train 전용)

생성기 training/data/sources/synthetic_v2.py, 출력 datasets/blade/processed/data_v2_synthetic_additions.jsonl 129건 (SHA-256 `3e6cee803968a5a062f5b834648f143560b46ed48f1ad707dd6c66d3f138c81c`), 원본 디렉토리 datasets/blade/raw/synthetic_v2/. train_v30/val_v30/test_v30은 변경하지 않았고 data-v2 동결 시 train_v2에 합친다. test 전용 서비스(quill_blog·folio_wiki·beacon_iot·summit_club) 도메인과 겹침 없음.

## A. 인가 검사 제거 변형 (train 전용 4개 서비스의 정상 구현마다)

세 종류: authonly(핸들러 내부 인증만, 인가 제거 → manual), extauth(인증이 핸들러 밖: FastAPI Depends / Express 미들웨어 / Spring @PreAuthorize, 인가 없음 → manual), extguard(외부 인증 + 원래 인가 검사 유지 → 원래 구체 label, 대조군). 발췌(raw_snippet)에는 핸들러와 함께 외부 인증 함수·미들웨어 정의를 포함한다. 구독 섹션은 v3.0 정의상 제외.

| 구분 | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required | 합계 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| campus_records_variants | 0 | 1 | 0 | 1 | 1 | 1 | 8 | 12 |
| copper_wallet_variants | 0 | 1 | 0 | 1 | 1 | 1 | 8 | 12 |
| orbit_tickets_variants | 0 | 1 | 0 | 1 | 1 | 1 | 8 | 12 |
| relay_forum_variants | 0 | 1 | 2 | 1 | 1 | 2 | 14 | 21 |

변형 종류별: {"authonly": 19, "extauth": 19, "extguard": 19}

## B. 신규 train 전용 서비스 4종 (프레임워크·인가 방식 다양화)

| 서비스 | 프레임워크 | 인가 방식 | 도메인 | OAS |
|---|---|---|---|---|
| harbor_manifests | Django REST | @permission_classes 데코레이터(IsAuthenticated/IsAdminUser/AllowAny) + ORM 필터(owner) + 핸들러 검사 | manifests | script_projection |
| pixel_gallery | NestJS | @UseGuards(AuthGuard, RolesGuard)·@Roles + 핸들러 검사 | artworks | script_projection |
| meadow_plots | Gin | 라우트 그룹 미들웨어 authRequired()·requireRole() + 핸들러 검사 | plots | script_projection |
| atlas_leases | Rails | before_action :authenticate!/:require_admin! + ORM scope(current_user.records) + 액션 검사 | leases | script_projection |

각 18 엔드포인트: public 2, owner_match 2, owner_or_admin 4, tenant_match 2, role_required 2, membership_required 4(그룹 구성원), 복합 tenant AND membership → manual 2. archive 변형은 인가 검사 생략(취약, intended label 유지·known_vulnerable=true).

| 구분 | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required | 합계 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| harbor_manifests | 2 | 2 | 4 | 2 | 2 | 4 | 2 | 18 |
| pixel_gallery | 2 | 2 | 4 | 2 | 2 | 4 | 2 | 18 |
| meadow_plots | 2 | 2 | 4 | 2 | 2 | 4 | 2 | 18 |
| atlas_leases | 2 | 2 | 4 | 2 | 2 | 4 | 2 | 18 |

## 합계

| 구분 | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required | 합계 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 전체 | 8 | 12 | 18 | 12 | 12 | 21 | 46 | 129 |

인증이 핸들러 밖에 있는 레코드 102건. OAS: 프레임워크 export 33건(FastAPI), 스크립트 투영본 96건(오프라인에서 Django/Nest/Gin/Rails 실행 불가, 투영본임을 meta.oas_status에 기록).

## 한계

- 신규 4종은 실행·테스트하지 않은 템플릿 코드다(프레임워크 미설치). 문법은 각 프레임워크 관용구를 따르되 컴파일·실행 검증은 없다.
- 라벨은 설계 의도(intended_labels)이며 사람 확정 전이다. confidence 1.0은 설계 표시다.
- 정상 구현의 archive 취약 변형은 기존 규약대로 intended label을 유지한다(코드만 보면 manual이 맞는 사례; 학습 시 label 선택은 data-v2 동결 때 결정).
