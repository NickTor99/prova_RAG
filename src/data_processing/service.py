from fastapi import FastAPI

# The file where NeuralSearcher is stored
from src.data_processing.contract_searcher import ContractSearcher

app = FastAPI()

# Create a neural searcher instance
contract_searcher = ContractSearcher(collection_name="vulnerable_contracts")


@app.get("/api/search_all")
def search_startup(q: str):
    return {"result": contract_searcher.search(text=q)}

@app.get("/api/search_vulns")
def search_startup(q: str):
    return {"result": contract_searcher.search_vulns(text=q)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)