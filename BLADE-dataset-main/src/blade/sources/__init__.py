"""외부 데이터 소스 fetcher.

각 모듈은 fetch() 함수를 노출하고, 결과는 RawItem(dict) 리스트로 반환한다.
RawItem 표준 키:
    id, source, cve_id, title, description, cwe_id, severity,
    cvss_score, attack_vector, url, updated_at,
    (옵션) _preclassified: dict — fetcher 가 미리 채운 enrichment 결과
"""
