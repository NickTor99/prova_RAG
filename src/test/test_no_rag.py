from src.utils import *
import os
from src.llm_interface.client import get_code_analysis, get_code_analysis2
import re
test_folder = "../../data/algorand_contracts"


def test_no_rag(sub_folder):
    contract_path = os.path.join(test_folder, sub_folder)

    vulnerability_name = map_vulnerability(sub_folder)  # Map folder name to a readable vulnerability name

    print(f"{vulnerability_name} vulnerability{20 * '-'}")

    results = []
    for file in os.listdir(contract_path):
        file_path = os.path.join(contract_path, file)
        contract = open_contract(file_path)  # Load the contract content
        #print(f"📌 Results for {file}:")

        code = contract['smart_contract']

        response = get_code_analysis(code)

        # Converti ciascuna vulnerabilità in un dizionario
        detected_vulns_dicts = [vuln.model_dump(mode='json') for vuln in response]

        d = {
            "contract_id": file,
            "detected_vulns": detected_vulns_dicts
        }
        results.append(d)


    return results

def test_no_rag2(sub_folder):
    contract_path = os.path.join(test_folder, sub_folder)

    vulnerability_name = map_vulnerability(sub_folder)  # Map folder name to a readable vulnerability name

    print(f"{vulnerability_name} vulnerability{20 * '-'}")

    results = []
    for file in os.listdir(contract_path):
        file_path = os.path.join(contract_path, file)
        contract = open_contract(file_path)  # Load the contract content
        #print(f"📌 Results for {file}:")

        code = contract['smart_contract']

        response = get_code_analysis2(code)

        res = re.split(r"```list", response)[1].strip()
        res = re.split(r"```", res)[0].strip()
        try:
            data = json.loads(res)
        except json.JSONDecodeError as e:
            data = []

        print(data)


def test_all():
    list = []

    for sub_folder in os.listdir(test_folder):
        vulnerability_name = map_vulnerability(sub_folder)
        results = test_no_rag(sub_folder)

        list.append(
            {
                "name": vulnerability_name,
                "results": results
            }
        )

    with open("../../results/algorand_results/results_no_rag.json", "w", encoding="utf-8") as file:
        json.dump(list, file, indent=4, ensure_ascii=False)




list = test_no_rag2("rekey_to")
"""
for v in list:
    print(v['contract_id'])
    for v1 in v['detected_vulns']:
        print(f"📌 Results for {v1['name']} -> Confidence: {v1['confidence']}")"""


