from utils import open_contract
import re
import json
def split_global_and_functions(lines):
    global_code = []
    function_code = []
    in_function = False
    functions = []


    for line in lines:
        # Riconosce l'inizio di una funzione
        if re.match(r"^\t*def\s+\w", line):
            # Salva la funzione precedentemente rilevata
            if len(function_code) > 0:
                code = "\n".join([line for line in function_code if line.strip()])
                functions.append(code)
            function_code = []
            in_function = True
        if not in_function:
            global_code.append(line)  # Mantiene il codice globale
        else:
            function_code.append(line)  # Mantiene le righe appartenenti alle funzioni

    # Salva l'ultima funzione del contratto
    code = "\n".join([line for line in function_code if line.strip()])
    functions.append(code)

    #Stringa delle variabili globali
    global_code = "\n".join([line for line in global_code if line.strip()])

    results = {
        "global": global_code,
        "functions": functions
    }

    return results

def get_global_vars(code):
    # Dizionario per memorizzare le dichiarazioni
    declarations = {}

    # Espressione regolare per catturare la dichiarazione completa
    pattern = r"(\w+)\s*=\s*.*"

    # Itera sulle righe di codice e aggiunge le dichiarazioni al dizionario
    for line in code.split("\n"):
        match = re.match(pattern, line.strip())
        if match:
            var_name = match.group(1)  # Nome della variabile
            declarations[var_name] = line.strip()  # Intera riga della dichiarazione

    # Stampa il dizionario risultante
    return declarations

def add_global_var_in_chunk(chunk,globals):
    found = ""
    for name,decl in globals.items():
        if name in chunk:
            found += f"{decl}\n"

    return found+'\n'+chunk

def get_chunk(contract_code, max_chunk_size=800):
    """
    Divide un contratto PyTeal in chunk mantenendo le parti rilevanti per l'analisi delle vulnerabilità.
    - Mantiene dichiarazioni globali.
    - Rimuove il blocco `if __name__ == '__main__':`.
    """
    # Rimuove tutto ciò che segue il blocco `if __name__ == '__main__':`
    contract_code = re.split(r"\nif\s+__name__\s*==\s*['\"]__main__['\"]:", contract_code)[0].strip()

    lines = contract_code.split("\n")

    # Separa le dichiarazioni globali dalle funzioni
    results = split_global_and_functions(lines)

    globals = results['global']
    functions = results['functions']

    chunks = []

    for fun in functions:
        print(len(fun))
        chunk = add_global_var_in_chunk(fun,get_global_vars(globals))
        chunks.append(chunk)

    return chunks

# Esempio di utilizzo
contract_code = open_contract("pyteal_contracts/pyteal1.json")['smart_contract']

chunks = get_chunk(contract_code)

i=1
for chunk in chunks:
    print(f"{'-'*20}CHUNK {i}{'-'*20}")
    print(chunk)
    i+=1


