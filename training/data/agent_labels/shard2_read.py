import json,sys,re
sys.stdout.reconfigure(encoding='utf-8')
rows=[json.loads(x) for x in open('datasets/blade/processed/apisguru_filtered.jsonl',encoding='utf-8')]
for i in range(int(sys.argv[1]),min(int(sys.argv[2]),len(rows))):
    if i%3!=2: continue
    x=rows[i]
    erd=x['erd_snippet'].replace('\n',' ').replace('   ',' ')
    for a,b in [(' TEXT','~T'),(' INTEGER','~I'),(' NUMERIC','~N'),(' BOOLEAN','~B'),(' -- owner candidate','~O'),(' -- tenant candidate','~E')]: erd=erd.replace(a,b)
    print(i,x['service'],x['method'],x['path'],x['oas_snippet'],erd)
