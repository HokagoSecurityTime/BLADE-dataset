import json
from pathlib import Path
import chromadb
from chromadb.utils import embedding_functions

DOC_PATH = Path("data/processed/chroma_documents.json")
CHROMA_PATH = "chroma_db"
COLLECTION_NAME = "blade_cve_kb"
BATCH_SIZE = 100

def chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]

def main():
    client = chromadb.PersistentClient(path=CHROMA_PATH)

    # 임베딩 모델 명시 (나중에 보안 특화 모델로 교체 가능)
    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
        metadata={"description": "BLADE CVE knowledge base"}
    )

    with open(DOC_PATH, "r", encoding="utf-8") as f:
        docs = json.load(f)

    print(f"적재 대상 문서 수: {len(docs)}")

    added = 0
    skipped = 0

    for batch in chunks(docs, BATCH_SIZE):
        ids = [d["id"] for d in batch]
        documents = [d["document"] for d in batch]
        metadatas = [d["metadata"] for d in batch]

        # 이미 있는 문서는 건너뜀
        existing = collection.get(ids=ids)
        existing_ids = set(existing.get("ids", []))

        new_ids, new_documents, new_metadatas = [], [], []

        for doc_id, document, metadata in zip(ids, documents, metadatas):
            if doc_id not in existing_ids:
                new_ids.append(doc_id)
                new_documents.append(document)
                new_metadatas.append(metadata)
            else:
                skipped += 1

        if new_ids:
            collection.add(
                ids=new_ids,
                documents=new_documents,
                metadatas=new_metadatas,
            )
            added += len(new_ids)

    print(f"\n적재 완료")
    print(f"  새로 추가: {added}개")
    print(f"  중복 건너뜀: {skipped}개")
    print(f"  현재 collection 총 문서 수: {collection.count()}")

if __name__ == "__main__":
    main()