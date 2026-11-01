import re, json, sys, yaml
from pathlib import Path
from collections import defaultdict

ROOT = Path(sys.argv[1])          # .../openapi-directory/APIs
OUT  = Path(sys.argv[2])          # .../raw/apisguru_candidates.jsonl
MAX_PER_SERVICE = 15

ID_PARAM = re.compile(r'(^id$|_id$|Id$|^uuid$|_uuid$|Uuid$|Key$|_key$)', re.I)
OWNER_COLS  = re.compile(r'^(user_?id|owner_?id|created_?by|author_?id|account_?id|customer_?id|member_?id)$', re.I)
TENANT_COLS = re.compile(r'^(tenant_?id|org_?id|organization_?id|company_?id|workspace_?id|team_?id|project_?id)$', re.I)
METHODS = {"get","post","put","patch","delete"}

class OpenAPILoader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):
    """OpenAPI object keys are strings, even plain YAML keys such as on/off."""
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                raise ValueError("OpenAPI requires scalar object keys")
            result[key_node.value] = self.construct_object(value_node, deep=deep)
        return result

def load(p):
    try:
        with open(p, encoding="utf-8") as f:
            return yaml.load(f, Loader=OpenAPILoader)
    except Exception:
        return None

def deref(spec, obj, depth=0):
    if depth > 5 or not isinstance(obj, dict): return obj
    if "$ref" in obj:
        parts = obj["$ref"].lstrip("#/").split("/")
        node = spec
        for k in parts:
            node = node.get(k, {}) if isinstance(node, dict) else {}
        return deref(spec, node, depth+1)
    return obj

def schema_fields(spec, schema, acc, depth=0):
    schema = deref(spec, schema)
    if not isinstance(schema, dict) or depth > 3: return
    for k in ("allOf","oneOf","anyOf"):
        for s in schema.get(k, []): schema_fields(spec, s, acc, depth+1)
    for name, prop in (schema.get("properties") or {}).items():
        prop = deref(spec, prop)
        acc[name] = (prop.get("type") or "object") if isinstance(prop, dict) else "any"
        if isinstance(prop, dict) and prop.get("type") == "object":
            schema_fields(spec, prop, acc, depth+1)
    if schema.get("type") == "array" and "items" in schema:
        schema_fields(spec, schema["items"], acc, depth+1)

def response_schema(spec, op):
    for code in ("200","201","default"):
        r = deref(spec, (op.get("responses") or {}).get(code, {}))
        if not r: continue
        if "content" in r:
            for _, media in r["content"].items():
                if "schema" in media: return media["schema"]
        if "schema" in r: return r["schema"]
    return None

def to_ddl(resource, fields):
    cols = []
    for n, t in fields.items():
        if isinstance(t, list):
            non_null = [kind for kind in t if kind != "null"]
            t = non_null[0] if len(non_null) == 1 else "object"
        sql = {"integer":"INTEGER","number":"NUMERIC","boolean":"BOOLEAN"}.get(t, "TEXT")
        tag = ""
        if OWNER_COLS.match(n): tag = " -- owner candidate"
        elif TENANT_COLS.match(n): tag = " -- tenant candidate"
        cols.append(f"  {n} {sql}{tag}")
    return f"CREATE TABLE {resource} (\n" + ",\n".join(cols) + "\n);"

if __package__:
    from .naming import resource_name
else:
    from naming import resource_name

records, per_service = [], defaultdict(int)
files = list(ROOT.rglob("openapi.yaml")) + list(ROOT.rglob("swagger.yaml"))
for fp in files:
    service = fp.relative_to(ROOT).parts[0]
    if per_service.get(service, 0) >= MAX_PER_SERVICE: continue
    spec = load(fp)
    if not spec or "paths" not in spec: continue
    if per_service[service] >= MAX_PER_SERVICE: continue
    for path, item in (spec["paths"] or {}).items():
        if not isinstance(item, dict): continue
        path_params = re.findall(r"\{([^}]+)\}", path)
        for m, op in item.items():
            if m not in METHODS or not isinstance(op, dict): continue
            q = [p.get("name") for p in (op.get("parameters") or []) if isinstance(p, dict) and p.get("in") == "query"]
            id_params = [p for p in path_params + q if p and ID_PARAM.search(p)]
            if not id_params: continue
            fields = {}
            rs = response_schema(spec, op)
            if rs: schema_fields(spec, rs, fields)
            if not fields:   # 응답 스키마 없으면 요청 바디
                rb = deref(spec, op.get("requestBody", {}))
                for _, media in (rb.get("content") or {}).items():
                    if "schema" in media: schema_fields(spec, media["schema"], fields)
            if not fields: continue
            res = resource_name(path)
            rec = {
                "id": f"apisguru:{service}:{m}:{path}",
                "service": service,
                "method": m.upper(),
                "path": path,
                "oas_snippet": json.dumps({
                    "summary": op.get("summary") or op.get("description", "")[:300],
                    "operationId": op.get("operationId"),
                    "tags": op.get("tags"),
                    "security": op.get("security", spec.get("security")),
                    "path_params": path_params,
                    "query_params": q,
                }, ensure_ascii=False),
                "erd_snippet": to_ddl(res, fields),
                "controller_signals": None,
                "label": None,
                "rationale": None,
                "meta": {
                    "object_param_candidates": id_params,
                    "has_owner_col": any(OWNER_COLS.match(f) for f in fields),
                    "has_tenant_col": any(TENANT_COLS.match(f) for f in fields),
                    "has_security": bool(op.get("security", spec.get("security"))),
                    "source_file": str(fp.relative_to(ROOT)),
                },
            }
            records.append(rec); per_service[service] += 1
            if per_service[service] >= MAX_PER_SERVICE: break
        if per_service[service] >= MAX_PER_SERVICE: break

OUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    for r in records: f.write(json.dumps(r, ensure_ascii=False) + "\n")

n = len(records)
print(f"specs scanned: {len(files)}")
print(f"records: {n}  services: {len(per_service)}")
print(f"owner col: {sum(r['meta']['has_owner_col'] for r in records)}  tenant col: {sum(r['meta']['has_tenant_col'] for r in records)}  security: {sum(r['meta']['has_security'] for r in records)}")
from collections import Counter
print("methods:", Counter(r["method"] for r in records))
