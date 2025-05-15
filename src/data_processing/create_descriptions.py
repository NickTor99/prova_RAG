from openai import OpenAI
import os
from src.utils import open_contract
import json
from src.llm_interface.client import get_code_description

client = OpenAI(
    api_key="sk-36dc60b2590248549d81a309aaf3f912",
    base_url="https://api.deepseek.com"
)

test_folder = "../../data/algorand_contracts"

descriptions = []

for directory in os.listdir(test_folder):

    sub_folder = os.path.join(test_folder, directory)
    for file in os.listdir(sub_folder):
        file_path = os.path.join(sub_folder, file)
        contract = open_contract(file_path)
        contract_code = contract['smart_contract']
        vuln = contract['vulnerability']

        if vuln == "no vuln":
            continue

        print(f"📌 Description for {file} done!")

        description = get_code_description(contract_code)

        data = {
            'contract_id': file,
            'code': contract_code,
            'vulnerability': vuln,
            'description': description
        }
        descriptions.append(data)

with open("../../data/descriptions.json", "w", encoding="utf-8") as file:
    json.dump(descriptions, file, indent=4, ensure_ascii=False)
