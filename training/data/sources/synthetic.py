"""Generate six isolated runnable authorization fixtures; never generate test.jsonl."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[3]
SERVICES = [('quill_blog','fastapi','entries'), ('orbit_tickets','fastapi','reservations'),
            ('folio_wiki','express','pages'), ('copper_wallet','express','transfers'),
            ('campus_records','spring','transcripts'), ('beacon_iot','django','sensors')]
LABELS = ['public','owner_match','owner_or_admin','tenant_match','role_required','membership_required','manual_review_required']
REASONS = {'public':'Intentionally anonymous reference catalogue.', 'owner_match':'Only the record owner may read it.',
 'owner_or_admin':'The record owner or an administrator may read it.', 'tenant_match':'Caller and record must share a tenant.',
 'role_required':'Only administrators may read this operational resource.', 'membership_required':'A premium plan is required.',
 'manual_review_required':'Conflicting owner and tenant requirements are deliberately unresolved; deny pending review.'}
PY_CHECK = {'owner_match':'principal["id"] != obj["owner_id"]',
 'owner_or_admin':'principal["id"] != obj["owner_id"] and principal["role"] != "admin"',
 'tenant_match':'principal["tenant_id"] != obj["tenant_id"]','role_required':'principal["role"] != "admin"',
 'membership_required':'principal["plan"] != "premium"','manual_review_required':'True'}
PRINCIPALS = {'alice':{'id':'alice','tenant_id':'north','role':'user','plan':'premium'},
 'bob':{'id':'bob','tenant_id':'south','role':'user','plan':'free'},
 'admin':{'id':'root','tenant_id':'north','role':'admin','plan':'premium'}}

def write(base, name, value):
    path=base/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(value,encoding='utf-8')

def endpoints(name, noun):
    sections = ['catalogue', 'drafts', 'shared', 'workspace', 'audit', 'subscription', 'disputed']
    return [dict(id=f'{name}_{sections[k]}_{i}', method='GET', path=f'/fixtures/{name}/{noun}/{sections[k]}/{"current" if i==0 else "archive"}/{{item_id}}',
                 label=label, vulnerable=(i==1 and label not in {'public','manual_review_required'}), reason=REASONS[label])
            for k,label in enumerate(LABELS) for i in range(2)]

def python_app(base,name,rows,django=False):
    if django:
        pre='from rest_framework.decorators import api_view\nfrom rest_framework.response import Response\nfrom drf_spectacular.utils import extend_schema\nfrom django.urls import path\n'
    else: pre='from fastapi import FastAPI, Header, HTTPException\napp = FastAPI(title='+repr(name)+')\n'
    pre+='PRINCIPALS = '+repr(PRINCIPALS)+'\n'
    pre+='OBJECTS = {"1": {"id":"1","owner_id":"alice","tenant_id":"north","value":"fixture secret"}, "2": {"id":"2","owner_id":"bob","tenant_id":"south","value":"other secret"}}\n'
    pre+='def principal_for(token):\n    return PRINCIPALS.get(token.removeprefix("Bearer "))\n\n'
    code=pre
    for row in rows:
        fn=row['id']; label=row['label']; path=row['path']
        if django:
            code+=f'@extend_schema(description={row["reason"]!r}, responses={{200: dict}})\n@api_view(["GET"])\ndef {fn}(request, item_id):\n    authorization = request.headers.get("Authorization", "")\n'
        else: code+=f'@app.get({path!r}, description={row["reason"]!r})\ndef {fn}(item_id: str, authorization: str = Header(default="")):\n'
        fail=lambda status: f'return Response({{"detail":"denied"}}, status={status})' if django else f'raise HTTPException({status})'
        code+='    obj = OBJECTS.get(item_id)\n    if obj is None: '+fail(404)+'\n'
        if label!='public':
            code+='    principal = principal_for(authorization)\n    if principal is None: '+fail(401)+'\n'
            if row['vulnerable']: code+='    # Deliberate fixture: object authorization check omitted.\n'
            else: code+='    if '+PY_CHECK[label]+': '+fail(403)+'\n'
        code+='    return '+('Response(obj)' if django else 'obj')+'\n\n'
    if django:
        code+='urlpatterns = [\n'+''.join(f'    path({r["path"].lstrip("/").replace("{item_id}","<str:item_id>")!r}, {r["id"]}),\n' for r in rows)+']\n'
        write(base,'api.py',code)
        write(base,'settings.py','SECRET_KEY="local-synthetic-fixture"\nDEBUG=False\nALLOWED_HOSTS=["*"]\nROOT_URLCONF="urls"\nINSTALLED_APPS=["django.contrib.auth","django.contrib.contenttypes","rest_framework","drf_spectacular"]\nDATABASES={"default":{"ENGINE":"django.db.backends.sqlite3","NAME":":memory:"}}\nREST_FRAMEWORK={"DEFAULT_SCHEMA_CLASS":"drf_spectacular.openapi.AutoSchema","DEFAULT_AUTHENTICATION_CLASSES":[],"UNAUTHENTICATED_USER":None}\n')
        write(base,'urls.py','from api import urlpatterns\nfrom django.urls import path\nfrom drf_spectacular.views import SpectacularAPIView\nurlpatterns += [path("openapi.json", SpectacularAPIView.as_view())]\n')
        write(base,'manage.py','import os,sys\nos.environ.setdefault("DJANGO_SETTINGS_MODULE","settings")\nfrom django.core.management import execute_from_command_line\nexecute_from_command_line(sys.argv)\n')
        requirements='Django>=5.1,<5.3\ndjangorestframework>=3.15,<3.17\ndrf-spectacular>=0.28,<0.29\n'
        command='["python","manage.py","runserver","0.0.0.0:8080","--noreload"]'
        export='python manage.py spectacular --file openapi.yaml --validate'
    else:
        write(base,'app.py',code); requirements='fastapi>=0.115,<1\nuvicorn>=0.30,<1\n'; command='["uvicorn","app:app","--host","0.0.0.0","--port","8080"]'
        write(base,'export_openapi.py','import json\nfrom app import app\nfrom pathlib import Path\nPath("openapi.json").write_text(json.dumps(app.openapi(),indent=2))\n'); export='python export_openapi.py'
    write(base,'requirements.txt',requirements)
    write(base,'Dockerfile','FROM python:3.11-slim\nWORKDIR /fixture\nCOPY requirements.txt .\nRUN pip install --no-cache-dir -r requirements.txt\nCOPY . .\nRUN '+export+'\nEXPOSE 8080\nCMD '+command+'\n')
    return 'api.py' if django else 'app.py'

def express_app(base,name,rows):
    code='const express = require("express");\nconst swaggerJsdoc = require("swagger-jsdoc");\nconst fs = require("fs");\nconst app = express();\nconst principals = '+json.dumps(PRINCIPALS)+';\nconst objects = {"1":{id:"1",owner_id:"alice",tenant_id:"north",value:"fixture secret"},"2":{id:"2",owner_id:"bob",tenant_id:"south",value:"other secret"}};\n'
    for row in rows:
        code+='/**\n * @openapi\n * '+row['path']+':\n *   get:\n *     description: '+row['reason']+'\n *     parameters:\n *       - in: path\n *         name: item_id\n *         required: true\n *         schema: {type: string}\n *     responses:\n *       200:\n *         description: Fixture record\n */\n'
        code+=f'app.get({json.dumps(row["path"].replace("{item_id}",":item_id"))}, function {row["id"]}(req,res) {{\n  const obj = objects[req.params.item_id];\n  if (!obj) return res.sendStatus(404);\n'
        if row['label']!='public':
            code+='  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];\n  if (!principal) return res.sendStatus(401);\n'
            if row['vulnerable']: code+='  // Deliberate fixture: object authorization check omitted.\n'
            else:
                check=PY_CHECK[row['label']].replace(' != ',' !== ').replace(' and ',' && ').replace('True','true')
                code+='  if ('+check+') return res.sendStatus(403);\n'
        code+='  return res.json(obj);\n});\n'
    code+='const spec = swaggerJsdoc({definition:{openapi:"3.0.3",info:{title:'+json.dumps(name)+',version:"1.0.0"}},apis:[__filename]});\nif (process.argv.includes("--export")) fs.writeFileSync("openapi.json",JSON.stringify(spec,null,2));\nelse { app.get("/openapi.json",(req,res)=>res.json(spec)); app.listen(8080,"0.0.0.0"); }\n'
    write(base,'app.js',code); write(base,'package.json',json.dumps({'private':True,'dependencies':{'express':'^4.21.2','swagger-jsdoc':'^6.2.8'}}))
    write(base,'Dockerfile','FROM node:22-alpine\nWORKDIR /fixture\nCOPY package.json .\nRUN npm install --omit=dev\nCOPY . .\nRUN node app.js --export\nEXPOSE 8080\nCMD ["node","app.js"]\n'); return 'app.js'

def spring_app(base,name,rows):
    code='package fixture;\nimport java.util.Map;\nimport org.springframework.boot.SpringApplication;\nimport org.springframework.boot.autoconfigure.SpringBootApplication;\nimport org.springframework.web.bind.annotation.*;\nimport org.springframework.web.server.ResponseStatusException;\nimport org.springframework.http.HttpStatus;\n@SpringBootApplication\n@RestController\npublic class App {\n public static void main(String[] args) { SpringApplication.run(App.class,args); }\n record Principal(String id,String tenant_id,String role,String plan) {}\n static final Map<String,Principal> principals=Map.of("alice",new Principal("alice","north","user","premium"),"bob",new Principal("bob","south","user","free"),"admin",new Principal("root","north","admin","premium"));\n static final Map<String,Map<String,String>> objects=Map.of("1",Map.of("id","1","owner_id","alice","tenant_id","north","value","fixture secret"),"2",Map.of("id","2","owner_id","bob","tenant_id","south","value","other secret"));\n'
    checks={'owner_match':'!principal.id().equals(obj.get("owner_id"))','owner_or_admin':'!principal.id().equals(obj.get("owner_id")) && !principal.role().equals("admin")','tenant_match':'!principal.tenant_id().equals(obj.get("tenant_id"))','role_required':'!principal.role().equals("admin")','membership_required':'!principal.plan().equals("premium")','manual_review_required':'true'}
    for row in rows:
        code+=' @GetMapping("'+row['path']+'")\n public Map<String,String> '+row['id']+'(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {\n  var obj=objects.get(item_id);\n  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);\n'
        if row['label']!='public':
            code+='  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));\n  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);\n'
            code+=('  // Deliberate fixture: object authorization check omitted.\n') if row['vulnerable'] else ('  if('+checks[row['label']]+') throw new ResponseStatusException(HttpStatus.FORBIDDEN);\n')
        code+='  return obj;\n }\n'
    code+='}\n'; write(base,'src/main/java/fixture/App.java',code)
    write(base,'pom.xml','<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.4.4</version></parent><groupId>fixture</groupId><artifactId>campus</artifactId><version>1.0</version><properties><java.version>21</java.version></properties><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency><dependency><groupId>org.springdoc</groupId><artifactId>springdoc-openapi-starter-webmvc-ui</artifactId><version>2.8.6</version></dependency></dependencies><build><plugins><plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>')
    write(base,'Dockerfile','FROM maven:3.9-eclipse-temurin-21 AS build\nWORKDIR /fixture\nCOPY . .\nRUN mvn -q -DskipTests package\nFROM eclipse-temurin:21-jre\nWORKDIR /fixture\nCOPY --from=build /fixture/target/campus-1.0.jar app.jar\nEXPOSE 8080\nCMD ["java","-jar","app.jar"]\n')
    write(base,'export_openapi.py','import urllib.request\nfrom pathlib import Path\nPath("openapi.json").write_bytes(urllib.request.urlopen("http://localhost:18084/v3/api-docs").read())\n'); return 'src/main/java/fixture/App.java'

def generate(root=ROOT):
    records=[]; compose={'name':'blade-synthetic','services':{}}
    for index,(name,framework,noun) in enumerate(SERVICES):
        base=root/'datasets/blade/raw/synthetic'/name; rows=endpoints(name,noun)
        handler=python_app(base,name,rows,framework=='django') if framework in {'fastapi','django'} else express_app(base,name,rows) if framework=='express' else spring_app(base,name,rows)
        # Executable model definition is the source of the generated DDL, shared across languages.
        model='from dataclasses import dataclass, fields\n@dataclass\nclass Record:\n    id: str\n    owner_id: str\n    tenant_id: str\n    value: str\n\ndef ddl():\n    return "CREATE TABLE '+name+'_'+noun+' (" + ", ".join(f.name + " TEXT" + (" PRIMARY KEY" if f.name == "id" else " NOT NULL") for f in fields(Record)) + ");"\n\nif __name__ == "__main__":\n    from pathlib import Path\n    Path(__file__).with_name("schema.sql").write_text(ddl())\n'
        write(base,'model.py',model); ns={}; exec(compile(model,'model.py','exec'),ns); ddl=ns['ddl'](); write(base,'schema.sql',ddl+'\n')
        write(base,'intended_labels.yaml',yaml.safe_dump({'service':name,'endpoints':rows},sort_keys=False))
        lines=(base/handler).read_text(encoding='utf-8').splitlines()
        for row in rows:
            start=next(i for i,line in enumerate(lines) if row['id']+'(' in line)
            end=next((i for i in range(start+1,len(lines)) if lines[i].startswith(('def ',' public Map','app.get(','@app.','@extend_schema',' @GetMapping'))),len(lines))
            block=lines[start:end]; evidence_index=next((i for i,line in enumerate(block) if 'FORBIDDEN' in line or '403' in line or 'Deliberate fixture' in line),max(0,len(block)-3))
            absolute_line=start+evidence_index+1; excerpt='\n'.join(block[evidence_index:evidence_index+3]).strip()
            rel=(base/handler).relative_to(root).as_posix()
            signals={'has_auth_check':row['label']!='public','admin_bypass':row['label']=='owner_or_admin' and not row['vulnerable'],'tenant_check':row['label']=='tenant_match' and not row['vulnerable'],'owner_filter':row['label'] in {'owner_match','owner_or_admin'} and not row['vulnerable']}
            records.append({**row,'source':'synthetic','service':name,'proposed_label':row['label'],'label':None,'confirmed_label':None,'notes':'','rationale':row['reason'],'evidence':[{'file':rel,'line':absolute_line,'code':excerpt}], 'source_file':rel,'source_line':absolute_line,'code_excerpt':excerpt,'code_evidence':True,'controller_signals':signals,'known_vulnerable':row['vulnerable'],'known_vulnerable_source':str((base/'intended_labels.yaml').relative_to(root)).replace('\\','/'),'erd_snippet':ddl,'meta':{'known_vulnerable':row['vulnerable'],'exclude':False,'label_source':'intended_labels','vulnerability_intentionally_injected':row['vulnerable']}})
        compose['services'][name]={'build':{'context':base.relative_to(root).as_posix()},'ports':[f'127.0.0.1:{18080+index}:8080'],'restart':'no'}
        write(base,'README.md',f'# {name}\n\nLocal synthetic fixture. Bearer tokens: alice (north, premium), bob (south, free), admin (north, admin). Objects 1/alice/north and 2/bob/south. All data is in memory; POST writes are intentionally outside this fixture. Secure routes enforce intended_labels.yaml; variant routes omit the indicated authorization check. Manual-review routes deny access because the fixture policy is unresolved.\n\nBuild/run from repository root: `docker compose -f docker-compose.test.yml up --build {name}`. Host port {18080+index}, localhost only. OpenAPI is generated by the framework tool, not a hand-written specification. '+('Run `python export_openapi.py` after the service starts to save springdoc output.' if framework=='spring' else 'The Docker build exports OpenAPI; the running service also exposes its schema.')+'\n')
    write(root,'docker-compose.test.yml',yaml.safe_dump(compose,sort_keys=False))
    write(root,'verification/synthetic_review_records.jsonl',''.join(json.dumps(row,ensure_ascii=False)+'\n' for row in records))
    write(root,'verification/synthetic_generation_report.json',json.dumps({'total':len(records),'services':{name:14 for name,_,_ in SERVICES},'known_vulnerable':sum(r['known_vulnerable'] for r in records),'runtime_validation':'pending; framework exports require dependencies'},indent=2))
    return records

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--root',type=Path,default=ROOT)
    args=parser.parse_args(); print(json.dumps({'generated':len(generate(args.root))}))
