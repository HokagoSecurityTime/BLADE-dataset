POLICY_TEMPLATES = {
    "owner_match": {
        "description": "리소스 소유자와 요청자가 같아야 함",
        "example": "resource.owner_id == jwt.sub",
    },
    "tenant_match": {
        "description": "리소스와 요청자가 같은 테넌트/조직에 속해야 함",
        "example": "resource.tenant_id == jwt.tenant_id",
    },
    "role_required": {
        "description": "특정 역할만 접근 가능",
        "example": "jwt.role in allowed_roles",
    },
    "membership_required": {
        "description": "프로젝트/팀 멤버만 접근 가능",
        "example": "jwt.sub in project.member_ids",
    },
    "owner_or_admin": {
        "description": "소유자 또는 관리자만 접근 가능. 일반 소유권 검증으로 부족할 때",
        "example": "resource.owner_id == jwt.sub OR jwt.role == admin",
    },
    "manual_review_required": {
        "description": "자동 판단 어려움. 관리자 검토 필요",
        "example": "manual review",
    },
}