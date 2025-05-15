import json
import os.path

import numpy as np
# Import client library
from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance
from sentence_transformers import SentenceTransformer

print("Caricamento del modello di Embeddings...")

encoder = SentenceTransformer(
    "hkunlp/instructor-xl", device="cuda"
)

instruction = "Represent the semantic behavior of the smart contract for similarity-based retrieval."

client = QdrantClient("http://localhost:6333")

if not client.collection_exists("vulnerable_contracts"):
    print("Creazione della collection...")
    client.create_collection(
        collection_name="vulnerable_contracts",
        vectors_config=VectorParams(
            size=encoder.get_sentence_embedding_dimension(),  # Vector size is defined by used model,
            distance=Distance.COSINE
        ),
    )

with open("../../data/descriptions.json", "r", encoding="utf-8") as file:
    data = json.load(file)

np_file = "../../data/description_vectors.npy"
if not os.path.exists(np_file):
    print("Creazione dei vettori di embeddings...")
    vectors = []
    for d in data:
        input_data = [[instruction, d['description']]]
        vectors.append(encoder.encode(input_data,show_progress_bar=True)[0])

    np.save(np_file, vectors, allow_pickle=False)

vectors = np.load(np_file)

print("Upload della collection...")
client.upload_collection(
    collection_name="vulnerable_contracts",
    vectors=vectors,
    payload=data,
    ids=None,  # Vector ids will be assigned automatically
)

