from openai import OpenAI
from instructor import IterableModel
import instructor
from pydantic import (
    BaseModel,
    Field,
)
from src.llm_interface.bool_vulnerability import BoolVulnerability2


class Vulnerability(BaseModel):
    name: str = Field(..., description="Vulnerability name that has been detected")
    description: str = Field(..., description="Vulnerability description that has been detected")
    confidence: float = Field(..., ge=0.0, le=1.0,
                              description="Confidence score between 0 and 1, that the vulnerability is actually present")


# Creazione di una classe che gestisce una lista di vulnerabilità
VulnerabilityList = IterableModel(Vulnerability)

client_instructor = instructor.from_openai(
    OpenAI(
        api_key="sk-36dc60b2590248549d81a309aaf3f912",
        base_url="https://api.deepseek.com"
    ),
    mode=instructor.Mode.JSON,
)

client = OpenAI(
    api_key="sk-36dc60b2590248549d81a309aaf3f912",
    base_url="https://api.deepseek.com"
)


def get_code_analysis(code):
    sys_prompt = """
You are an expert in smart contract security auditing for Algorand, specifically analyzing PyTeal code.

Your task is to examine the following PyTeal smart contract code and determine whether any of the following known vulnerabilities are likely to be present:

- Arbitrary delete: restrict deletion to the creator or fully disable deletion.
- Arbitrary update: restrict updates to the creator or fully disable updates.
- Unchecked Asset Close To: validate that all authorized asset transfers ensure `asset_close_to` is either `Global.zero_address()` or a predefined safe address.
- Unchecked Close Remainder To: ensure that **Payment transactions** authorized by the stateless contract explicitly validate `close_remainder_to` to prevent arbitrary closure of the account. This typically means verifying it equals `Global.zero_address()`, or—if closing is an intended feature—only allowing specific, trusted addresses.
- Unchecked Rekey to: ensure that **all payment and asset transfer transactions** explicitly verify that their `rekey_to` field is set to `Global.zero_address()`. This requirement applies to both `Txn.rekey_to()` and `Gtxn[i].rekey_to()` forms.
- Unchecked Transaction Fee: ensure that **all critical transactions** has cap fees.
- Unchecked Asset Receiver: ensure asset transfer only go to whitelisted addresses.
- Unchecked Payment Receiver: ensure payments only go to whitelisted addresses.

Furthermore return the names of the vulnerabilities that are **most likely present** using this format, ordered from most to least critical :
```list
["Vulnerability_name1", "Vulnerability_name2", ...]
```
"""

    user_prompt=f"""
Now analyze this contract, make sure you analyze every field of the all transactions. If a critical check is missing report it:

{code}
    """

    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {
                "role": "system",
                "content": sys_prompt
            },
            {
                "role": "user",
                "content": user_prompt,
            }
        ],
        temperature=0.0,
    )

    return response.choices[0].message.content


def get_code_formatted_analysis(code):
    sys_prompt = """
You are an expert in smart contract security auditing for Algorand, specifically analyzing PyTeal code.
Make sure you analyze every field in the transactions

- Unchecked Asset Close To
- Unchecked Close Remainder To
- Unchecked Rekey to
- Unchecked Transaction Fee
- Unchecked Asset Receiver
- Unchecked Payment Receiver
- Arbitrary delete
- Arbitrary update

For each potential vulnerability that could realistically apply, return an instance of the `Vulnerability` class defined below. If a vulnerability is clearly mitigated or not applicable, omit it from the output.

Include a `confidence` value between 0.0 and 1.0 to indicate how likely it is that the vulnerability is actually present, based on the absence or incorrect implementation of relevant security checks.

Use the following output schema:

class Vulnerability(BaseModel):
    name: str = Field(..., description="Vulnerability name that has been detected")
    description: str = Field(..., description="Vulnerability description that has been detected")
    confidence: float = Field(..., ge=0.0, le=1.0,
                              description="Confidence score between 0 and 1, that the vulnerability is actually present")

VulnerabilityList = IterableModel(Vulnerability)

Only output a `VulnerabilityList` containing the detected vulnerabilities with confidence > 0.0.

"""
    user_prompt = "Please analyze the following PyTeal smart contract for security vulnerabilities."
    response = client_instructor.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {
                "role": "system",
                "content": sys_prompt
            },
            {
                "role": "user",
                "content": f"{user_prompt}\n\n{code}",
            }
        ],
        response_model=VulnerabilityList,
        temperature=0.0,
        max_retries=5
    )
    return response


def get_code_description(code):
    sys_prompt = """
You are a security-focused code analysis assistant specializing in Algorand smart contracts written in PyTeal.
Your primary objective is to analyze provided PyTeal code snippets and generate comprehensive, structured descriptions that encapsulate the code's functionalities, 
managed transaction types and usage contexts. 
These descriptions will be instrumental in retrieving and comparing code segments with similar functionalities.
"""

    user_prompt = """
The following code is an Algorand smart contract written in PyTeal.

Analyze it and return a structured list of its key behaviors, using **short, general, technical statements**, following these rules:

- Output must be a list of 3–10 bullet points.
- Each point should describe one functional behavior or access condition.
- Focus on core logic, state changes, transaction restrictions, and control flows.
- Focus on the checks performed on all transaction fields involved (in all group transactions if any). Highlight any missing checks, but only if such checks are required (e.g., close_remainder_to, asset_close_to, rekey_to, transaction_fee, etc.).
- If all relevant checks for a specific field across all transactions are properly implemented, explicitly state that.
- Do **not** include variable or function names, implementation details, or code syntax.
- **If the contract handles grouped transactions, describe field-level checks per transaction position** (e.g., "Transaction 0", "Transaction 1", etc.). For each one, list the verified fields. If a field is not checked and could lead to misuse, indicate clearly: **"Missing check: [field_name]"**.
- Conclude with a summary of overall coverage, such as:  
  - "All transactions correctly restrict rekeying to the zero address."  
  - "Some transactions are missing close_remainder_to checks."

The output should be concise and use consistent structure, like:

- "Approves transaction only if sender is authorized."
- "Updates global state based on a fixed comparison."
- "Rejects transaction if a required argument is missing."
- "Allows asset transfer under specific condition."
- "Checks if the payment amount matches an expected value."

Code to analyze:

"""
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {
                 "role": "system",
                 "content": sys_prompt
            },
            {
                "role": "user",
                "content": f"{user_prompt}\n{code}",
            }],
        temperature=0.0  # Riduci randomness
    )
    return response.choices[0].message.content


def get_vuln_analysis(user_prompt):

    sys_prompt = """
You are an expert in Algorand smart contract (ASC) security analysis. Your task is to analyze provided Algorand smart contract code for potential vulnerabilities, following a three-step process.

**Instructions for Analysis:**

**Input:** You will be provided with Algorand smart contract code (in PyTeal or TEAL) and a specific vulnerability to assess.

**Output:** Your analysis must strictly adhere to the following three steps:

### Step 1 – Contract Type Classification:

* **Determine the contract type:** Classify the provided code as either a **smart signature** or a **smart contract (application)**. Explain your reasoning based on the code structure and functionality (e.g., presence of `Approve()`, global/local state, `OnComplete` actions).
* **Describe the contract's functionality:** Based on the code, explain what the contract is designed to do. Identify its primary purpose and the actions it enables. Analyze the logic and the different execution paths.

### Step 2 – Vulnerability Assessment:

* **Check Applicability:** Based on the contract type identified in Step 1 and the contract's functionality, determine if the specific vulnerability you are instructed to check is potentially applicable to this type of contract and its logic. Explain why or why not. For example, a vulnerability related to application state manipulation would not be applicable to a stateless smart signature.
* **Analyze for the Specific Vulnerability:** Carefully examine the provided code for the presence and potential exploitation of the specific vulnerability you are instructed to assess. Provide specific code snippets and reasoning to support your findings. Consider all possible execution paths and transaction scenarios.

### Step 3 – Final Evaluation:

* **Determine Vulnerability Status:** Based on the analysis in Step 2, conclude whether the contract is:
    * **Vulnerable:** If the vulnerability is clearly present and exploitable within the contract's logic.
    * **Not Vulnerable:** If the vulnerability is not applicable to the contract type or its logic, or if the code effectively prevents its exploitation.
    * **Potentially Vulnerable:** If there are ambiguities in the code or potential scenarios that could lead to the vulnerability, but further context or analysis might be required for a definitive conclusion. Clearly explain the reasons for this classification.

**Important Considerations:**

* Pay close attention to transaction types (`TxnType`), group transactions (`Gtxn`), application calls (`Txn.application_args`, `OnComplete`), state management (global and local), and control flow within the contract.
* Assume the provided code is a complete and functional part of an Algorand application or represents the logic of a smart signature.
* Be precise and provide clear justifications for each step of your analysis.
* Only analyze for the specific vulnerability mentioned in the prompt. Do not perform a general security audit unless explicitly asked.
"""

    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {
                "role": "system",
                "content": sys_prompt
            },
            {
                "role": "user",
                "content": user_prompt,
            }],
        temperature=0.0  # Riduci randomness
    )
    return response.choices[0].message.content


def get_vuln_formatted_analysis(user_prompt):

    sys_prompt = """
You are an advanced security auditor specialized in smart contracts written in PyTeal (Algorand's contract language).
Your task is to analyze a given smart contract and determine whether it is vulnerable to a specific security issue.

Use the following assessment protocol:

### Step 1 – Contract Type Classification

Carefully analyze the provided PyTeal code and determine whether it implements one of the following:

#### 🔹 Stateless Smart Contract (LogicSig or Contract Account)
A LogicSig is a PyTeal program used to authorize transactions without maintaining any application state. It is typically characterized by:

- Returning a single boolean expression, such as And(...), Or(...), Return(Int(1)), or Return(Txn.sender() == Global.creator_address()), or a Seq(...) ending with Return(...).
- Does not use any App.* operations like App.globalGet, App.globalPut, App.localGet, App.localPut.
- Does not define or use OnCompletion handlers (handle_creation, handle_optin, handle_closeout, handle_updateapp, handle_deleteapp, handle_call).

Vulnerabilities that may affect Stateless Smart Contract:

- Unchecked Asset Close To (asset_close_to)
- Unchecked Close Remainder To (close_remainder_to)
- Unchecked Rekey to (rekey_to)
- Unchecked Transaction Fee (transaction_fee)
- Unchecked Asset Receiver (Unchecked_Asset_Receiver)
- Unchecked Payment Receiver (Unchecked_Payment_Receiver)

#### 🔹 Stateful Smart Contract (Application)
An Algorand application that manages persistent state and lifecycle events. It is characterized by:

- Using App.* operations such as App.globalGet, App.globalPut, App.localGet, App.localPut.
- Defining and handling lifecycle events via OnCompletion handlers (NoOp, OptIn, CloseOut, UpdateApplication, DeleteApplication, etc.).
- Deployed with a unique Application ID and often interacts with global or local storage.

Vulnerabilities that may affect Stateful Smart Contracts:

- Arbitrary delete (arbitrary_delete)
- Arbitrary update (arbitrary_update)
- Unchecked Transaction Fee (transaction_fee)
- Unchecked Rekey to (rekey_to)
- Unchecked Asset Receiver (Unchecked_Asset_Receiver)
- Unchecked Payment Receiver (Unchecked_Payment_Receiver)

---

### Step 2 – Vulnerability Assessment:
If the vulnerability is applicable, check whether the required security check is present.

---

### Step 3 – Final Evaluation:
Based on your previous conclusion return the answer in this format
```json
{
  "reasoning": "<write down all the reasoning you made>"
  "vulnerability_name": "<standardized name of the vulnerability being tested>",
  "status": "vulnerable" | "not vulnerable" | "potential vulnerable",
  "description": "<concise technical explanation including reasoning and checks observed or missing>"
}
"""

    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {
                "role": "system",
                "content": sys_prompt
            },
            {
                "role": "user",
                "content": user_prompt,
            }],
        temperature=0.0  # Riduci randomness
    )
    return response.choices[0].message.content



