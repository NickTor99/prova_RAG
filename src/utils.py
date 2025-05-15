import json
import os
import sys
import random
from src.llm_interface.client import get_code_description


def open_contract(path):
    # Open and read the JSON file
    with open(path, 'r') as file:
        data = json.load(file)
    return data


def get_random_vuln():
    with open("../data/json_files/algorand_vuln_info.json", "r") as file:
        data = json.load(file)
    return random.choice(data['vulnerabilities'])['name']


def get_vuln_details(vuln):
    # Ottiene la directory in cui si trova questo script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Costruisce il percorso assoluto al file JSON
    file_path = os.path.join(script_dir, "..", "data", "json_files", "algorand_vuln_info.json")
    # Normalizza il percorso per rimuovere eventuali componenti ridondanti
    file_path = os.path.normpath(file_path)
    with open(file_path, "r") as file:
        data = json.load(file)
    for d in data['vulnerabilities']:
        if d['name'] == vuln:
            return d


def progress_bar(completed, total, length=50, task="Task"):
    cmpl = ""
    if completed == total:
        cmpl = "✅ COMPLETED"
    percentage = (completed / total)
    filled_length = int(length * percentage)
    bar = "█" * filled_length + "-" * (length - filled_length)
    sys.stdout.write(f"\r[{bar}] {percentage * 100:.2f}% {task} {cmpl}")
    sys.stdout.flush()


def map_vulnerability(name):
    mapping = {
        "arbitrary_delete": "Arbitrary delete",
        "arbitrary_update": "Arbitrary update",
        "asset_close_to": "Unchecked Asset Close To",
        "close_remainder_to": "Unchecked Close Remainder To",
        "rekey_to": "Unchecked Rekey to",
        "transaction_fee": "Unchecked Transaction Fee",
        "Unchecked_Asset_Receiver": "Unchecked Asset Receiver",
        "Unchecked_Payment_Receiver": "Unchecked Payment Receiver",
        "no vuln": "Not Vulnerable"
    }

    return mapping.get(name, "Unknown")


def map_vulnerability_inverted(name):
    mapping = {
        "Arbitrary delete": "arbitrary_delete",
        "Arbitrary update": "arbitrary_update",
        "Unchecked Asset Close To": "asset_close_to",
        "Unchecked Close Remainder To": "close_remainder_to",
        "Unchecked Rekey to": "rekey_to",
        "Unchecked Transaction Fee": "transaction_fee",
        "Unchecked Asset Receiver": "Unchecked_Asset_Receiver",
        "Unchecked Payment Receiver": "Unchecked_Payment_Receiver",
    }

    return mapping.get(name, "Unknown")

#print(open_contract("C:\\Users\Smart\IdeaProjects\prova_RAG\data\\algorand_contracts\\Unchecked_Payment_Receiver\\pyteal41.json")['smart_contract'])

import datetime

x = datetime.datetime.now()


total_list = {
    'we': 'ciao',
    'x': x.strftime("%d/%m/%Y-%H:%M")
}

def get_file_name(base_file_name):
    # Ottiene la directory in cui si trova questo script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Costruisce il percorso assoluto al file JSON
    file_path = os.path.join(script_dir, "..", "results", "algorand_results")
    # Normalizza il percorso per rimuovere eventuali componenti ridondanti
    file_path = os.path.normpath(file_path)


    i=1
    while True:
        new_file = f"{base_file_name}{i}"
        if f"{new_file}.json" in os.listdir(file_path) or f"{new_file}.txt" in os.listdir(file_path):
            i = i+1
            continue
        else:
            break

    return new_file


