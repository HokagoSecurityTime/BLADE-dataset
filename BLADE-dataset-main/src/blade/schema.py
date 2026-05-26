"""통합 데이터 스키마.

3개 트랙(A: src/, B: rag_scripts/, C: scripts/)의 metadata 키를 superset 으로 통합.
가이드 §3 (dataset_guide.md) 을 베이스로, 각 트랙 고유 필드(business_logic_complexity,
policy_template_hint, ownership_type 등)를 보존.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


# --- 키 상수 (오타 방지용 — retrieve/generate 코드에서 import 해서 사용) ----

class K:
    """Metadata 키 이름 상수. 코드에서 문자열 리터럴 대신 K.X 사용."""
    SOURCE = "source"
    SOURCE_TYPE = "source_type"
    SOURCE_ID = "source_id"
    CVE_ID = "cve_id"
    URL = "url"
    TITLE = "title"
    UPDATED_AT = "updated_at"

    CWE_ID = "cwe_id"
    SEVERITY = "severity"
    CVSS_SCORE = "cvss_score"
    ATTACK_VECTOR = "attack_vector"

    BOLA_PATTERN = "bola_pattern"

    ENDPOINT_PATTERN = "endpoint_pattern"
    HTTP_METHOD = "http_method"
    ID_TYPE = "id_type"
    ID_FORMAT = "id_format"
    OWNERSHIP_TYPE = "ownership_type"
    OWNERSHIP_CHECK_MISSING = "ownership_check_missing"
    ATTACK_METHOD = "attack_method"

    RULE_TYPE = "rule_type"
    RULE_BASED_DETECTABLE = "rule_based_detectable"
    INFERENCE_REQUIRED = "inference_required"
    BUSINESS_LOGIC_COMPLEXITY = "business_logic_complexity"
    DOMAIN = "domain"
    OWASP_MAPPING = "owasp_mapping"

    POLICY_TEMPLATE_HINT = "policy_template_hint"

    ENRICHMENT_METHOD = "enrichment_method"
    REASON = "reason"


# --- enum 후보값 (검증용) ------------------------------------------------

VALID_SOURCES = {
    "nvd", "cisa", "sheets",
    "cwe", "capec", "owasp_api", "wstg",
    "hackerone", "github",
    "business_logic",
}

VALID_SOURCE_TYPES = {"cve", "standard", "report", "pattern"}

VALID_BOLA_PATTERNS = {
    "integer_id_enumeration",
    "nested_resource_idor",
    "mass_assignment",
    "filter_param_bypass",
    "batch_unvalidated",
    "admin_path_exposure",
    "uuid_idor",
}

VALID_ID_TYPES = {"path_param", "query_param", "body_param", "unknown"}
VALID_ID_FORMATS = {"uuid", "integer_sequential", "string_slug", "unknown", ""}
VALID_OWNERSHIP_TYPES = {"direct", "hierarchical", "delegated", "role_based", "contextual", ""}
VALID_RULE_TYPES = {"jwt_ownership", "block_path", "rate_limit", "strip_body_field", "batch_size_limit", "query_param_override", ""}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE", "UNKNOWN", ""}

VALID_ENRICHMENT_METHODS = {"preclassified", "rule", "llm", "legacy"}


# --- dataclass ----------------------------------------------------------


@dataclass
class Metadata:
    # Provenance
    source: str = ""
    source_type: str = ""
    source_id: str = ""
    cve_id: str = ""
    url: str = ""
    title: str = ""
    updated_at: str = ""

    # Vulnerability classification
    cwe_id: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    attack_vector: str = ""

    # BOLA pattern (가이드 7 종)
    bola_pattern: str = ""

    # Endpoint / ownership
    endpoint_pattern: str = ""
    http_method: str = ""
    id_type: str = ""
    id_format: str = ""
    ownership_type: str = ""
    ownership_check_missing: str = ""
    attack_method: str = ""

    # Detection / policy hints
    rule_type: str = ""
    rule_based_detectable: bool = False
    inference_required: bool = True
    business_logic_complexity: int = 0
    domain: str = ""
    owasp_mapping: str = ""

    # A 트랙 정책 hint
    policy_template_hint: str = ""

    # Enrichment 메타
    enrichment_method: str = ""
    reason: str = ""

    def to_chroma_dict(self) -> dict[str, Any]:
        """ChromaDB metadata 는 scalar(str/int/float/bool) 만 허용.

        None/list/dict 등은 허용되지 않으므로 None → '' 로 치환한다.
        """
        out: dict[str, Any] = {}
        for k, v in asdict(self).items():
            if v is None:
                out[k] = ""
            elif isinstance(v, (str, int, float, bool)):
                out[k] = v
            else:
                out[k] = str(v)
        return out


@dataclass
class Record:
    """통합 데이터셋의 단일 레코드.

    id 규칙: "{source}-{native_id}"  예) "nvd-CVE-2022-34770", "hackerone-12345"
    document: ChromaDB 임베딩 대상 텍스트
    """
    id: str
    document: str
    metadata: Metadata = field(default_factory=Metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "document": self.document,
            "metadata": asdict(self.metadata),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Record":
        md_raw = d.get("metadata", {}) or {}
        # 알려진 키만 채우고 모르는 키는 무시 (legacy 호환)
        known = {f for f in Metadata.__dataclass_fields__}
        md = Metadata(**{k: v for k, v in md_raw.items() if k in known})
        return cls(id=d["id"], document=d.get("document", ""), metadata=md)


# --- 파일 I/O ----------------------------------------------------------


def load_records(path: Path) -> list[Record]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return [Record.from_dict(d) for d in data]


def dump_records(records: Iterable[Record], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in records], f, ensure_ascii=False, indent=2)


# --- document 텍스트 빌더 (가이드 §4 형식) ------------------------------


def build_document_text(meta: Metadata, description: str) -> str:
    """ChromaDB 임베딩 대상 텍스트 생성.

    가이드 §4-2 의 영문 단일 청크 포맷. 빈 필드는 표시하지 않아 노이즈를 줄인다.
    """
    lines: list[str] = []
    sid = meta.source_id or meta.cve_id
    if meta.source or sid:
        lines.append(f"source: {meta.source}  source_id: {sid}")
    if meta.endpoint_pattern or meta.http_method:
        lines.append(f"endpoint: {meta.http_method} {meta.endpoint_pattern}".strip())
    if meta.id_type or meta.id_format:
        lines.append(f"id_type: {meta.id_type} ({meta.id_format})")
    if meta.ownership_type or meta.ownership_check_missing:
        lines.append(
            f"ownership: {meta.ownership_type} - {meta.ownership_check_missing}".rstrip(" -")
        )
    if meta.attack_method or meta.bola_pattern:
        lines.append(f"attack: {meta.attack_method} ({meta.bola_pattern})")
    if meta.cwe_id or meta.owasp_mapping or meta.severity:
        lines.append(
            f"cwe: {meta.cwe_id}  owasp: {meta.owasp_mapping}  "
            f"severity: {meta.severity} ({meta.cvss_score})"
        )
    if description:
        lines.append(f"description: {description}")
    return "\n".join(lines)
