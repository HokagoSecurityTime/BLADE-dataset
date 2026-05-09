"""ChromaDB 클라이언트 헬퍼.

source_type 별로 컬렉션을 분할(가이드 §4-5) 하고, source 라벨로 라우팅한다.
"""

from __future__ import annotations

from typing import Iterable

import chromadb
from chromadb.api.client import Client
from chromadb.api.models.Collection import Collection

from blade import config


def get_client(path: str | None = None) -> Client:
    """PersistentClient 인스턴스. path 지정 없으면 config.CHROMA_PATH 사용."""
    p = str(path) if path else str(config.CHROMA_PATH)
    config.CHROMA_PATH.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=p)


def get_collection(client: Client, name: str) -> Collection:
    """컬렉션 get-or-create. cosine 거리 사용."""
    return client.get_or_create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},
    )


def get_all_collections(client: Client) -> dict[str, Collection]:
    """가이드 §4-5 의 3-컬렉션을 한꺼번에 준비."""
    return {name: get_collection(client, name) for name in config.ALL_COLLECTIONS}


def collection_for_source(source: str) -> str:
    """source → 컬렉션 이름 매핑. 미지의 source 는 CVE 컬렉션으로."""
    return config.SOURCE_TO_COLLECTION.get(source, config.COLLECTION_CVE)


def query_all(
    client: Client,
    *,
    query_embedding: list[float],
    n_results: int = 5,
    collection_names: Iterable[str] | None = None,
) -> list[dict]:
    """모든(또는 지정된) 컬렉션을 병렬 검색해 거리 기준으로 합쳐 반환.

    각 결과: {id, document, metadata, distance, collection}
    """
    names = list(collection_names) if collection_names else list(config.ALL_COLLECTIONS)
    merged: list[dict] = []
    for name in names:
        col = get_collection(client, name)
        if col.count() == 0:
            continue
        res = col.query(
            query_embeddings=[query_embedding],
            n_results=min(n_results, col.count()),
        )
        for i in range(len(res["ids"][0])):
            merged.append(
                {
                    "id": res["ids"][0][i],
                    "document": res["documents"][0][i],
                    "metadata": res["metadatas"][0][i],
                    "distance": res["distances"][0][i],
                    "collection": name,
                }
            )
    merged.sort(key=lambda x: x["distance"])
    return merged[:n_results]
