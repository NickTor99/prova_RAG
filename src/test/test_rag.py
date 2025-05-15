from src.llm_interface.client import *
from src.utils import *
import requests
import re

def get_possible_vulnerabilities2(code):
    # Prima analisi del codice da parte del modello per trovare possibili vulnerabilità
    response = get_code_analysis(code)
    res = re.split(r"```list", response)[1].strip()
    res = re.split(r"```", res)[0].strip()
    try:
        model_results = json.loads(res)
    except json.JSONDecodeError as e:
        model_results = []

    # Inizio parte di Retrieval
    description = get_code_description(code)  # Otteniamo la descrizione del codice in linguaggio naturale

    retrieval_results = {}
    url = "http://localhost:8000/api/search_vulns"
    params = {'q': description}
    response = requests.get(url,
                            params=params)  # Query al DataBase Vettoriale per trovare il codice vulnerabile più simile a quello in input
    if response.status_code == 200:
        jstr = json.loads(response.text)
        for j in jstr['result']:
            if file != j['contract_id']: # Escudiamo lo stesso file dal retrieval, dato che i contratti nel DB sono gli stessi del test (altrimenti il test sarebbe falsato)
                name = map_vulnerability(j['vulnerability'])
                retrieval_results[name] = j['score']
    else:
        print(f"Errore nella richiesta: {response.status_code}")

    top1 = model_results[:2]  # Prendiamo solo i primi 2 risultati con score più alto
    top2 = list(retrieval_results)[:2]

    # Somma dei 2 risultati -> Abbiamo ottenuto il vettore con le possibili vulnerabilità, che andranno analizzate singolarmente
    for i in top2:
        if i not in top1:
            top1.append(i)

    return top1


test_folder = "../../data/algorand_contracts"

results_file_name = get_file_name("results_rag")

total_list = []


def write_in_file(str):
    print(str)
    with open(f"../../results/algorand_results/{results_file_name}.txt", "a", encoding="utf-8") as file:
        file.write(f"\n{str}")


for sub_folder in os.listdir(test_folder):
    contract_path = os.path.join(test_folder, sub_folder)
    vulnerability_name = map_vulnerability(sub_folder)  # Map folder name to a readable vulnerability name
    sub_folder_results = []
    for file in os.listdir(contract_path):
        result_list = []
        file_path = os.path.join(contract_path, file)
        contract = open_contract(file_path)  # Load the contract content
        write_in_file(f"📌 Results for {file} -> {vulnerability_name}")

        code = contract['smart_contract']

        possible_vulns = get_possible_vulnerabilities2(code)

        for vuln in possible_vulns:
            write_in_file(f"{'-'*20}Analisi vulnerabilità {vuln}{'-'*20}")
            vuln_id = map_vulnerability_inverted(vuln)
            if vuln_id == "Unknown":
                continue
            details = get_vuln_details(vuln_id)  # Get detailed information about the vulnerability
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
```
                  """
            result = get_vuln_analysis(prompt)
            print(result)

            write_in_file(result)
