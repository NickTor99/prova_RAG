import os
from src.utils import open_contract
import json
import requests
from src.llm_interface.client import get_code_description

test_folder = "../../data/algorand_contracts"
sub_folder = "close_remainder_to"
contract_path = os.path.join(test_folder, sub_folder)

print(f"Test Retrieval System for {sub_folder} vulnerability\n")

for file in os.listdir(contract_path):
    file_path = os.path.join(contract_path, file)
    contract = open_contract(file_path)
    contract_code = contract['smart_contract']

    print(f"📌 Retrieval Results for {file}:")

    description = get_code_description(contract_code)

    url = "http://localhost:8000/api/search_vulns"
    params = {'q': description}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        # Stampa il contenuto della risposta
        jstr = json.loads(response.text)
        for j in jstr['result']:
            if file != j['contract_id']:
                print(f"{j['vulnerability']} -> {j['score']}")
    else:
        print(f"Errore nella richiesta: {response.status_code}")

    print(f"{50*'-'}")