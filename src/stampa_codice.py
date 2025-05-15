import re

from utils import open_contract

print("Inserisci numero del contratto")
n = int(input())
dir = ""
if 1 <= n <= 5: dir = "arbitrary_delete"
if 5 < n <= 10: dir = "arbitrary_update"
if 10 < n <= 15: dir = "asset_close_to"
if 15 < n <= 20: dir = "close_remainder_to"
if 20 < n <= 25: dir = "no vuln"
if 25 < n <= 30: dir = "rekey_to"
if 30 < n <= 35: dir = "transaction_fee"
if 35 < n <= 40: dir = "Unchecked_Asset_Receiver"
if 40 < n <= 45: dir = "Unchecked_Payment_Receiver"


contract_code = open_contract(f"../data/algorand_contracts/{dir}/pyteal{n}.json")['smart_contract']
#contract_code = re.split(r"\nif\s+__name__\s*==\s*['\"]__main__['\"]:", contract_code)[0].strip()
print(contract_code)
