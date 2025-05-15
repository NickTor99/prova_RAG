from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer


class ContractSearcher:
    def __init__(self, collection_name):
        self.collection_name = collection_name
        # Initialize encoder model
        self.model = SentenceTransformer("hkunlp/instructor-xl", device="cuda")
        # initialize Qdrant client
        self.qdrant_client = QdrantClient("http://localhost:6333")

    def search(self, text: str):
        # Convert text query into vector
        vector = self.model.encode(text).tolist()

        # Use `vector` for search for closest vectors in the collection
        search_result = self.qdrant_client.query_points(
            collection_name=self.collection_name,
            query=vector,
            query_filter=None,  # If you don't want any filters for now
            limit=40,  # 5 closest results is enough
        ).points
        # `search_result` contains found vector ids with similarity scores along with the stored payload
        # In this function you are interested in payload only
        payloads = [hit.payload for hit in search_result]
        return payloads

    def search_vulns(self, text: str):
        # Convert text query into vector
        vector = self.model.encode(text).tolist()

        # Use `vector` for search for closest vectors in the collection
        search_result = self.qdrant_client.query_points(
            collection_name=self.collection_name,
            query=vector,
            query_filter=None,  # If you don't want any filters for now
            limit=40,  # 6 closest results is enough
        ).points
        # `search_result` contains found vector ids with similarity scores along with the stored payload
        # In this function you are interested in payload only
        vulns = []
        for hit in search_result:
            vulns.append({"contract_id": hit.payload['contract_id'],"vulnerability":hit.payload['vulnerability'],"score": round(hit.score,3)})
        return vulns