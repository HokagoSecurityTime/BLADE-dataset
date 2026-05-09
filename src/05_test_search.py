import chromadb
from chromadb.utils import embedding_functions

CHROMA_PATH = "chroma_db"
COLLECTION_NAME = "blade_cve_kb"

TEST_QUERIES = [
    "API endpoint allows users to access another user's order by changing orderId in URL",
    "User can view other tenant's data by modifying organization ID",
    "Missing authorization check on DELETE endpoint allows deleting other users resources",
]

def main():
    client = chromadb.PersistentClient(path=CHROMA_PATH)

    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

    collection = client.get_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
    )

    print(f"총 문서 수: {collection.count()}\n")

    for query in TEST_QUERIES:
        print("=" * 80)
        print(f"쿼리: {query}\n")

        result = collection.query(
            query_texts=[query],
            n_results=3,
        )

        for i in range(len(result["ids"][0])):
            meta = result["metadatas"][0][i]
            print(f"  [{i+1}] {meta['cve_id']}")
            print(f"       패턴: {meta['attack_pattern']}")
            print(f"       추천 정책: {meta['recommended_policy']}")
            print(f"       심각도: {meta['severity']} (CVSS: {meta['cvss_score']})")
            print(f"       거리: {result['distances'][0][i]:.4f}")
            print()

if __name__ == "__main__":
    main()