# Analisi di Sicurezza per Smart Contract Algorand

Questo progetto utilizza un modello di analisi automatica per individuare vulnerabilità nei contratti smart scritti in PyTeal. Utilizza un database vettoriale (Qdrant) per il retrieval di codice simile.

## ⚙️ Requisiti

- Python 3.8+
- Docker
- `pip` (per installare le librerie)

---

## 🚀 Istruzioni per l'Esecuzione

### 1️⃣ Installare i requisiti Python

All'interno dell'ambiente virtuale, eseguire:

```bash
pip install -r requirements.txt
```

### 2️⃣ Avviare il database vettoriale Qdrant tramite Docker

```bash
docker pull qdrant/qdrant
docker run -p 6333:6333 ^
    -v %cd%/qdrant_storage:/qdrant/storage ^
    qdrant/qdrant
```
Su macOS/Linux sostituire ^ con \ oppure eseguire tutto su una riga.

### 3️⃣ Popolare il database vettoriale
Eseguire lo script per popolare Qdrant con i contratti e le vulnerabilità note:

```bash
python src/data_processing/create_vector_db.py
```
