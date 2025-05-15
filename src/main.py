from src.llm_interface.client import *
from src.utils import *
import requests
import json
import os
import re

num_try = 4               # Numero totale di vulnerabilità da analizzare in profondità
model_impact = 0.5        # Quota delle vulnerabilità individuate dal modello da includere nell’analisi finale
retrieval_impact = 0.5    # Quota delle vulnerabilità individuate via retrieval da includere nell’analisi finale
num_model = int(num_try * model_impact)
num_retrieval = int(num_try * retrieval_impact)


# === Caricamento del contratto ===
test_dir = "C:\\Users\\Smart\\IdeaProjects\\prova_RAG\\data\\algorand_contracts\\asset_close_to"
file = "pyteal11.json"
contract_path = os.path.join(test_dir, file)
contract = open_contract(contract_path)
code = contract['smart_contract']


# === 1) Fase di discovery: il modello individua possibili vulnerabilità ===
print("Analisi iniziale di discovery del modello...")
response = get_code_analysis(code)
res = re.split(r"```list", response)[1].strip()
res = re.split(r"```", res)[0].strip()
try:
    model_results = json.loads(res)                # Lista di vulnerabilità con ranking del modello
except json.JSONDecodeError:
    model_results = []

top_model = model_results[:num_model]              # Seleziona i primi N risultati con il ranking più alto
print(f"Risultati del modello: {top_model}")


# === 2) Fase di retrieval: cerca contratti simili in archivio e ne eredita le vulnerabilità ===
print("Ricerca di Smart Contract simili nel DataBase...")
description = get_code_description(code)           # Descrizione in linguaggio naturale del contratto

retrieval_results = {}
url = "http://localhost:8000/api/search_vulns"
params = {'q': description}
response = requests.get(url, params=params)        # Query al database vettoriale

if response.status_code == 200:
    # Popola retrieval_results con {vulnerability_name: score}
    for j in json.loads(response.text)['result']:
        if file != j['contract_id']:               # Esclude il file corrente per evitare autovalutazione
            name = map_vulnerability(j['vulnerability'])
            retrieval_results[name] = j['score']
else:
    print(f"Errore nella richiesta: {response.status_code}")

top_retrieval = list(retrieval_results)[:num_retrieval]   # Primi N risultati del retrieval
print(f"Risultati del retrieval: {top_retrieval}")


# === 3) Fusione delle vulnerabilità individuate dal modello e dal retrieval ===
for vuln in top_retrieval:
    if vuln not in top_model:
        top_model.append(vuln)


# === 4) Analisi approfondita di ciascuna vulnerabilità selezionata ===
print("Analisi singololare delle vulnerabilità trovate...")
for vuln in top_model:
    print(f"{'-'*20}Analisi vulnerabilità {vuln}{'-'*20}")
    vuln_id = map_vulnerability_inverted(vuln)
    if vuln_id == "Unknown":
        continue

    details = get_vuln_details(vuln_id)            # Dettagli completi sulla vulnerabilità
    formatted_checks = "\n".join(details['security_check']['required_checks'])

    prompt = f"""
### Vulnerability to Analyze:
- **Name:** {vuln}
- **Description:** {details['description']}
- **Attack Scenario:** {details['attack_scenario']}

---

### Precondition for the Vulnerability:
{details['precondition']}

---

### Required Security Check:
- **Goal:** {details['security_check']['goal']}
- **Examples of Legitimate Checks:**
{formatted_checks}

---

### Contract to Analyze:

```pyteal
{code}
            """
    result = get_vuln_analysis(prompt) # Analisi mirata del modello
    print(result)
