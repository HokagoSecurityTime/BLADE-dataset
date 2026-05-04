"""bola_dataset.json 을 nomic-embed-text 로 임베딩해 ChromaDB 에 적재."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import requests

import chromadb

# --- 상수 -----------------------------------------------------------------

DATASET_PATH = Path(__file__).resolve().parent.parent / "bola_dataset.json"
# 기본은 프로젝트 루트 하위. D:/BLADE/chroma_db 같은 외부 경로를 쓰려면
# CHROMA_PATH 환경변수로 덮어쓰면 됨.
CHROMA_PATH = os.environ.get("CHROMA_PATH", "chroma_db")
COLLECTION_NAME = "bola_kb"
OLLAMA_EMBED_URL = "http://localhost:11434/api/embeddings"
EMBED_MODEL = "nomic-embed-text"


# --- helpers --------------------------------------------------------------


def _embed(text: str) -> list[float] | None:
    """nomic-embed-text 로 단일 텍스트 임베딩."""
    try:
        resp = requests.post(
            OLLAMA_EMBED_URL,
            json={"model": EMBED_MODEL, "prompt": text},
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        emb = data.get("embedding")
        if not emb:
            return None
        return list(map(float, emb))
    except Exception as exc:  # noqa: BLE001
        print(f"  [warn] embed failed: {exc}")
        return None


def _build_document(item: dict[str, Any]) -> str:
    """가이드 §3 스키마 기준: 데이터셋이 이미 document 필드를 갖고 있다."""
    return item.get("document", "") or ""


def _build_metadata(item: dict[str, Any]) -> dict[str, Any]:
    """ChromaDB metadata 는 scalar 만 허용 → None 은 빈 문자열로 치환."""
    raw_md = item.get("metadata") or {}
    md: dict[str, Any] = {}
    for k, v in raw_md.items():
        if v is None:
            md[k] = ""
        elif isinstance(v, (str, int, float, bool)):
            md[k] = v
        else:
            md[k] = str(v)
    return md


def _load_dataset(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"dataset not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("dataset root must be a list")
    return data


# --- 적재 -----------------------------------------------------------------


def run(
    dataset_path: Path = DATASET_PATH,
    chroma_path: str = CHROMA_PATH,
    collection_name: str = COLLECTION_NAME,
) -> int:
    """bola_dataset.json → ChromaDB 적재. 적재된 총 개수 반환."""
    print("=== BOLA KB embedder ===")
    print(f"  dataset:    {dataset_path}")
    print(f"  chroma:     {chroma_path}")
    print(f"  collection: {collection_name}")
    print(f"  model:      {EMBED_MODEL}")

    items = _load_dataset(dataset_path)
    print(f"  loaded {len(items)} items")

    Path(chroma_path).mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=chroma_path)
    collection = client.get_or_create_collection(name=collection_name)

    upserted = 0
    for idx, item in enumerate(items, 1):
        item_id = item.get("id")
        if not item_id:
            print(f"  [{idx}] skipped: missing id")
            continue

        try:
            document = _build_document(item)
            metadata = _build_metadata(item)
            embedding = _embed(document)
            if embedding is None:
                print(f"  [{idx}] {item_id}: embedding failed, skipped")
                continue

            collection.upsert(
                ids=[item_id],
                documents=[document],
                metadatas=[metadata],
                embeddings=[embedding],
            )
            upserted += 1
            print(f"  [{idx}/{len(items)}] upserted {item_id}")
        except Exception as exc:  # noqa: BLE001
            print(f"  [{idx}] {item_id}: skipped due to error: {exc}")
            continue

    total = collection.count()
    print(f"\nUpserted in this run: {upserted}")
    print(f"Total in collection {collection_name!r}: {total}")
    return total


if __name__ == "__main__":
    run()
