"""legacy/ 의 3 트랙 데이터를 새 통합 스키마로 변환.

입력:
  - legacy/data/raw/nvd_cves_raw.json                       (트랙 A 원본 NVD)
  - legacy/data/processed/chroma_documents.json             (트랙 A 가공)
  - legacy/dataset/bola_dataset.json                        (트랙 B 가이드 §3 형식)
  - legacy/dataset/chunks/bola_chunks.json                  (트랙 C 통합 청크)

출력:
  - data/raw/<source>.json   — 각 source 의 raw 항목
  - data/processed/bola_dataset.json — 통합 데이터셋 (Record 리스트)

규칙:
  - id 표준화: "{source}-{native_id}"  (예: nvd-CVE-2022-34770, hackerone-12345, capec-CAPEC-1)
  - 같은 id 가 여러 트랙에 있으면 정보 풍부도가 높은 쪽으로 머지 (필드 단위 비공백 우선)
  - 임베딩은 안 함 (이건 03_load_chroma 가 따로 처리)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

# scripts/_bootstrap 와 같은 효과 — tools/ 에서 src/blade 가 import 가능하게
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from blade import config
from blade.enrich import rules as enrich_rules
from blade.schema import Metadata, Record, build_document_text, dump_records


# --- legacy 파일 위치 ---------------------------------------------------

LEGACY = config.LEGACY_DIR
A_RAW = LEGACY / "data" / "raw" / "nvd_cves_raw.json"
A_DOCS = LEGACY / "data" / "processed" / "chroma_documents.json"
B_DATASET = LEGACY / "dataset" / "bola_dataset.json"
C_CHUNKS = LEGACY / "dataset" / "chunks" / "bola_chunks.json"


# --- 헬퍼 --------------------------------------------------------------


def _load(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        print(f"  [skip] {path} not found")
        return []
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        print(f"  [warn] {path}: root is not a list")
        return []
    return data


def _id_for(source: str, native: str) -> str:
    return f"{source}-{native}"


_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+", re.I)


def _extract_cve(text: str) -> str:
    m = _CVE_ID_RE.search(text or "")
    return m.group(0).upper() if m else ""


# --- 트랙 A: data/raw/nvd_cves_raw.json --------------------------------
# 형식: [{"cve": {"id":..., "descriptions":[{"lang":"en","value":...}], "weaknesses":[...], "metrics":{...}}}]


def from_legacy_a_raw(items: list[dict]) -> list[dict]:
    """A 트랙 NVD raw → 새 raw item 형식 (sources/nvd._to_raw 와 동일 형태)."""
    from blade.sources.nvd import _to_raw  # 재사용
    out: list[dict] = []
    for entry in items:
        cve = entry.get("cve") or entry  # 일부 항목이 평탄화돼있을 수 있음
        r = _to_raw(cve)
        if r:
            out.append(r)
    return out


# --- 트랙 A: data/processed/chroma_documents.json ----------------------
# 형식: [{"id": "CVE-...", "document": "...", "metadata": {cve_id, attack_pattern, recommended_policy, cwes, cvss_score, severity, source, ...}}]


def from_legacy_a_docs(items: list[dict]) -> list[Record]:
    out: list[Record] = []
    for it in items:
        md_raw = it.get("metadata") or {}
        cve_id = md_raw.get("cve_id") or it.get("id") or ""
        if not cve_id:
            continue
        new_id = _id_for("nvd", cve_id)
        md = Metadata(
            source="nvd",
            source_type="cve",
            source_id=new_id,
            cve_id=cve_id,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            title=cve_id,
            updated_at=md_raw.get("lastModified", ""),
            cwe_id=(md_raw.get("cwes") or "").replace(", ", "|"),
            severity=md_raw.get("severity", ""),
            cvss_score=float(md_raw.get("cvss_score") or 0.0),
            owasp_mapping="API1:2023",
            # A 의 attack_pattern(4종) 은 의미상 정책 hint 와 가까우므로 매핑
            policy_template_hint=md_raw.get("recommended_policy", "") or "",
            enrichment_method="legacy",
            reason="migrated from legacy/data/processed/chroma_documents.json",
        )
        # description 은 raw NVD 에서 파싱한 동일한 값을 document 로부터 추출하는 대신
        # 원본 도큐먼트를 그대로 쓰는 것이 손실이 없다. 단, build_document_text 와 형식을
        # 통일하기 위해 도큐먼트는 재구성하고 description 만 원본에서 잘라낸다.
        doc = it.get("document", "") or ""
        m = re.search(r"Original description:\s*(.+?)\n\nWeakness", doc, re.S)
        description = m.group(1).strip() if m else doc
        md.endpoint_pattern = ""  # A 는 endpoint 안 채움
        document = build_document_text(md, description=description)
        out.append(Record(id=new_id, document=document, metadata=md))
    return out


# --- 트랙 B: dataset/bola_dataset.json ---------------------------------
# 형식: 가이드 §3, 이미 새 스키마와 매우 유사. id 가 이미 "nvd-CVE-...", "hackerone-...", "cisa-..." 형태


def from_legacy_b(items: list[dict]) -> list[Record]:
    out: list[Record] = []
    for it in items:
        md_raw = it.get("metadata") or {}
        rec_id = it.get("id") or ""
        source = md_raw.get("source", "") or ""
        if not rec_id or not source:
            continue
        cve_id = md_raw.get("cve_id", "") or ""
        md = Metadata(
            source=source,
            source_type=config.SOURCE_TO_TYPE.get(source, ""),
            source_id=rec_id,
            cve_id=cve_id,
            url=md_raw.get("url", ""),
            title=md_raw.get("title", "") or cve_id,
            updated_at=md_raw.get("updated_at", ""),
            cwe_id=md_raw.get("cwe_id", "") or "",
            severity=md_raw.get("severity", "") or "",
            cvss_score=float(md_raw.get("cvss_score") or 0.0),
            attack_vector=md_raw.get("attack_vector", "") or "",
            bola_pattern=md_raw.get("bola_pattern", "") or "",
            endpoint_pattern=md_raw.get("endpoint_pattern", "") or "",
            id_type=md_raw.get("id_type", "") or "",
            ownership_check_missing=md_raw.get("ownership_check_missing", "") or "",
            attack_method=md_raw.get("attack_method", "") or "",
            rule_based_detectable=bool(md_raw.get("rule_based_detectable", False)),
            inference_required=bool(md_raw.get("inference_required", True)),
            owasp_mapping="API1:2023",
            enrichment_method="legacy",
            reason=md_raw.get("reason", "") or "migrated from legacy/dataset/bola_dataset.json",
        )
        # B 의 document 텍스트는 그대로 쓸 수 있지만, 가이드 §4 형식으로 통일하기 위해
        # description 만 추출하고 build_document_text 로 재구성
        legacy_doc = it.get("document", "") or ""
        # B 도큐먼트 형식: "{id}: {description} CWE: ... Pattern: ..."
        m = re.match(r"^[^:]+:\s*(.+?)\s*CWE:\s*", legacy_doc)
        description = m.group(1).strip() if m else legacy_doc
        document = build_document_text(md, description=description)
        out.append(Record(id=rec_id, document=document, metadata=md))
    return out


# --- 트랙 C: dataset/chunks/bola_chunks.json ---------------------------
# 형식: [{"id":"cve_cve_2012_5571_0000","document":"...","metadata":{source_type,source_id,rule_type,severity(float),cwe(pipe),owasp,domain,ownership_type,attack_method,business_logic_complexity}}]


_C_SRC_TYPE_TO_NEW_SOURCE = {
    "cve": "nvd",
    "cwe": "cwe",
    "capec": "capec",
    "owasp": "wstg",        # C 는 owasp 라벨에 WSTG 표준을 묶어둠
    "business_logic": "business_logic",
}


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def from_legacy_c(items: list[dict]) -> list[Record]:
    out: list[Record] = []
    for it in items:
        md_raw = it.get("metadata") or {}
        src_type = md_raw.get("source_type", "cve") or "cve"
        src_id = md_raw.get("source_id", "") or ""
        if not src_id:
            continue

        new_source = _C_SRC_TYPE_TO_NEW_SOURCE.get(src_type, "nvd")
        cve_id = src_id if src_id.upper().startswith("CVE-") else ""
        new_id = _id_for(new_source, src_id)

        score = 0.0
        try:
            score = float(md_raw.get("severity") or 0.0)
        except (TypeError, ValueError):
            pass

        md = Metadata(
            source=new_source,
            source_type=config.SOURCE_TO_TYPE.get(new_source, src_type),
            source_id=new_id,
            cve_id=cve_id,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
            title=src_id,
            cwe_id=md_raw.get("cwe", "") or "",
            severity=_severity_from_score(score),
            cvss_score=score,
            ownership_type=md_raw.get("ownership_type", "") or "",
            attack_method=md_raw.get("attack_method", "") or "",
            rule_type=md_raw.get("rule_type", "") or "",
            business_logic_complexity=int(md_raw.get("business_logic_complexity") or 0),
            domain=md_raw.get("domain", "") or "",
            owasp_mapping=md_raw.get("owasp", "") or "API1:2023",
            enrichment_method="legacy",
            reason="migrated from legacy/dataset/chunks/bola_chunks.json",
        )
        # C 의 document 형식: "CVE ID: ...\nSeverity: ...\nCWE: ...\nOWASP: ...\n...\nDescription: <desc>"
        legacy_doc = it.get("document", "") or ""
        m = re.search(r"Description:\s*(.+)$", legacy_doc, re.S)
        description = m.group(1).strip() if m else legacy_doc
        document = build_document_text(md, description=description)
        out.append(Record(id=new_id, document=document, metadata=md))
    return out


# --- 머지 (필드 단위 비공백 우선) --------------------------------------


def _merge(records: Iterable[Record]) -> list[Record]:
    """같은 id 의 여러 Record 를 필드 단위로 머지. 늦게 들어온 비공백 값으로 덮어씀."""
    by_id: dict[str, Record] = {}
    for r in records:
        prev = by_id.get(r.id)
        if prev is None:
            by_id[r.id] = r
            continue
        merged_md = Metadata(**vars(prev.metadata))
        for k, v in vars(r.metadata).items():
            if v in ("", 0, 0.0, False, None):
                continue
            if not getattr(merged_md, k):
                setattr(merged_md, k, v)
        # document: 더 긴 쪽 보존
        new_doc = r.document if len(r.document) > len(prev.document) else prev.document
        by_id[r.id] = Record(id=r.id, document=new_doc, metadata=merged_md)
    return list(by_id.values())


# --- main --------------------------------------------------------------


def run(*, write_raw: bool = True) -> tuple[int, dict[str, int]]:
    print("=== migrate_legacy ===")
    print(f"  legacy: {LEGACY}")
    print(f"  output dataset: {config.DATASET_PATH}")

    a_raw_items = _load(A_RAW)
    a_docs_items = _load(A_DOCS)
    b_items = _load(B_DATASET)
    c_items = _load(C_CHUNKS)
    print(
        f"  loaded: A_raw={len(a_raw_items)}, A_docs={len(a_docs_items)}, "
        f"B={len(b_items)}, C={len(c_items)}"
    )

    # raw 변환은 A_raw 만 (B/C 는 이미 enriched)
    a_raw = from_legacy_a_raw(a_raw_items)

    if write_raw:
        config.RAW_DIR.mkdir(parents=True, exist_ok=True)
        with config.RAW_NVD.open("w", encoding="utf-8") as f:
            json.dump(a_raw, f, ensure_ascii=False, indent=2)
        print(f"  saved raw NVD: {len(a_raw)} → {config.RAW_NVD.name}")

        # legacy 의 standards seed CSV 보존
        seed_src = LEGACY / "dataset" / "raw" / "bola_dataset.csv"
        if seed_src.exists():
            from shutil import copyfile
            copyfile(seed_src, config.RAW_STANDARDS_SEED)
            print(f"  copied standards seed → {config.RAW_STANDARDS_SEED.name}")

    # processed 변환
    a_recs = from_legacy_a_docs(a_docs_items)
    b_recs = from_legacy_b(b_items)
    c_recs = from_legacy_c(c_items)

    print(f"  records: A={len(a_recs)}, B={len(b_recs)}, C={len(c_recs)}")

    # 우선순위(머지 시 늦게 들어온 비공백이 우선): A → B → C
    # 즉 같은 CVE 면 C 의 ownership_type 등 풍부 필드가 살아남고, B 의 bola_pattern 도 유지
    all_recs = list(a_recs) + list(b_recs) + list(c_recs)
    merged = _merge(all_recs)
    print(f"  merged unique ids: {len(merged)}")

    dump_records(merged, config.DATASET_PATH)
    print(f"  wrote → {config.DATASET_PATH}")

    by_source: dict[str, int] = {}
    for r in merged:
        by_source[r.metadata.source] = by_source.get(r.metadata.source, 0) + 1
    return len(merged), by_source


if __name__ == "__main__":
    total, by_source = run()
    print("\n=== summary ===")
    print(f"  total: {total}")
    for s, n in sorted(by_source.items(), key=lambda x: -x[1]):
        print(f"    {s:<16} {n}")
