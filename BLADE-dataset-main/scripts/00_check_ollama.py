"""Ollama 데몬 연결 확인 + 필요 모델 설치 여부 체크."""

import _bootstrap  # noqa: F401

from blade import config
from blade.utils import ollama_client


def main() -> int:
    if not ollama_client.is_alive():
        print("Ollama 연결 실패")
        print(f"  URL: {config.OLLAMA_BASE_URL}")
        print("  → `ollama serve` 명령어로 데몬을 먼저 실행하세요")
        return 1

    print("Ollama 연결 성공!")
    print(f"  URL: {config.OLLAMA_BASE_URL}")
    models = ollama_client.list_models()
    print(f"  설치된 모델 ({len(models)}개):")
    for m in models:
        print(f"    - {m}")

    needed = [config.EMBED_MODEL, config.ENRICHMENT_MODEL, config.POLICY_MODEL]
    missing = [m for m in needed if not any(m in name for name in models)]
    if missing:
        print("\n[warn] 다음 모델이 누락되어 있습니다:")
        for m in missing:
            print(f"  ollama pull {m}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
