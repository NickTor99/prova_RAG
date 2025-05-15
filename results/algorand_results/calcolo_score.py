import json
import re

from src.utils import map_vulnerability


def calcola_score():
    with open("results_rag5.json", 'r') as file:
        data = json.load(file)

    tot_tp = 0
    tot_fp = 0
    tot_fn = 0
    tot_tn = 0

    for res_vuln in data['results']: #scorre le vulnerabilità
        sum_tp = 0
        sum_fp = 0
        sum_fn = 0
        sum_tn = 0
        num_true_vuln = 1
        name = res_vuln['name'].lower()
        for results in res_vuln['results']: #scorre i file
            tp = 0
            fp = 0
            fn = 0
            tn = 0
            for res in results['detected_vulns']: #scorre le vulnerabilità trovate

                status = res['status'].lower()

                if map_vulnerability(res['vulnerability_name']) == "Unknown":
                    vuln = res['vulnerability_name'].lower()
                else:
                    vuln = map_vulnerability(res['vulnerability_name']).lower()

                if name == "not vulnerable":
                    if status == "vulnerable":
                        fp = fp + 1
                else:
                    if status == "vulnerable" and vuln == name:
                        tp = tp + 1
                    if status == "vulnerable" and vuln != name:
                        fp = fp + 1
            fn = num_true_vuln - tp
            if fp > 0:
                tn = 0
            else:
                tn = 1

            sum_tp += tp
            sum_fp += fp
            sum_tn += tn
            sum_fn += fn

        if name == "not vulnerable":
            print(f"Risultati per {name}: \n True Negative: {sum_tn}\n False Positive: {sum_fp}")
        else:
            print(f"Risultati per {name}: \n True Positive: {sum_tp}\n False Positive: {sum_fp}\n False Negative: {sum_fn}")

        tot_tp += sum_tp
        tot_fp += sum_fp
        tot_fn +=  sum_fn
        tot_tn += sum_tn

    precision = tot_tp/(tot_tp+tot_fp)
    recall = tot_tp/(tot_tp+tot_fn)
    accuracy = (tot_tp+tot_tn)/(tot_tp+tot_fp+tot_fn+tot_tn)
    f1_score = 2*((precision*recall)/(precision+recall))
    print(f"\nPrecision: {round(precision*100,2)}%")
    print(f"Recall: {round(recall*100,2)}%")
    print(f"F1-Score: {round(f1_score*100,2)}%")
    print(f"Accuracy: {round(accuracy*100,2)}%")


def get_results():
    flag = False
    result = ""
    with open("results_rag6.txt", 'r') as file:
        for line in file:
            if "Results for" in line and "->" in line:
                if flag:
                    print(f"{file_name} -> {file_vuln}\n {'-'*20}{analyzed_vuln}{'-'*20}\n {result}")
                flag = False
                file_name = line.split("Results for")[1].split("->")[0].strip()
                vuln = re.search(r'->\s*(.+)$', line)
                if vuln:
                    file_vuln = vuln.group(1).strip()
            if "--------------------Analisi vulnerabilitÃ" in line:
                if flag:
                    print(f"{file_name} -> {file_vuln}\n {'-'*20}{analyzed_vuln}{'-'*20}\n {result}")
                flag = False
                analyzed_vuln = line.split("--------------------Analisi vulnerabilitÃ")[1].split("--------------------")[0]
                result = ""
            if "### Step 3" in line:
                flag = True
                continue
            if flag:
                result = f"{result}{line}"





get_results()