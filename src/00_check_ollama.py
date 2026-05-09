import requests

try:
    response = requests.get("http://localhost:11434/api/tags", timeout=5)
    models = response.json().get("models", [])
    print("ollama 연결 성공!")
    print("설치된 모델:")
    for m in models:
        print(f"  - {m['name']}")
except Exception as e:
    print(f"연결 실패: {e}")
    print("ollama serve 명령어로 서버 먼저 실행")