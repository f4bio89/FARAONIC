# FARAONIC

> **F**ramework for **A**nomaly **R**ecognition and **A**nalysis in **O**perational **N**etworks for **I**ndustrial **C**ybersecurity.

FARAONIC is a practical toolkit for monitoring **Industrial Control System (ICS)** traffic—especially **Modbus/TCP**—to build baselines, query/inspect data, and detect anomalies using **rules** and **machine learning** in real time.

* ⚙️ **Operational focus:** works with live traffic (pcap/sniff) and production-friendly JSON/CSV outputs.
* 🧠 **Two engines:** rule-based (baseline + detection) and behavioral (ML training + inference).
* 🧰 **Batteries included:** capture, upload to MongoDB, aggregation queries, model training, and live inference, all from a single launcher.

---

## Key Features

* **Unified launcher** (`faraonic.py`): interactive menu **and** CLI flags.
* **Baseline workflow (RULES):**

  * `01-captura.py` — capture Modbus/TCP traffic (BPF filters, summary/full).
  * `02-upload_mongodb.py` — upload JSON/JSONL to MongoDB in batches.
  * `03-perguntas.py` — baseline queries and summarization (JSON summary).
  * `04-deteccao.py` — real-time rule engine using the baseline.
* **Behavioral workflow (ML):**

  * `11-ML-v2.py` — robust training pipeline with safe defaults, time splits, optional GroupKFold, lightweight RandomizedSearch, feature importances, and Markdown reports.
  * `103-Executar-ML.py` — live or replay inference with safe JSONL writing, batch prediction, probability thresholds, and CSV output.
* **Operator UX:**

  * Friendly prompts with defaults and validation.
  * Logs persisted to `/logs` with timestamped files.
  * Clear error previews + “Show full log / Retry / Edit / Abort” loops.

---

## Project Layout

```
.
├── faraonic.py                 # Main launcher (menu + CLI)
├── 01-captura.py               # Capture (Modbus/TCP)
├── 02-upload_mongodb.py        # Upload baseline to MongoDB
├── 03-perguntas.py             # Baseline queries / summary
├── 04-deteccao.py              # Rule-based detector (live)
├── 11-ML-v2.py                 # ML training pipeline
├── 103-Executar-ML.py          # ML real-time/replay inference
├── ml_results/                 # Training reports (Markdown)
├── logs/                       # Run logs (auto-created)
└── dataset/                    # Example datasets (optional)
```

---

## Quick Start

> **Tip:** Use a dedicated Python virtual environment and keep **training and serving on the same scikit-learn version** to avoid pickle compatibility warnings.

```bash
# 1) Create & activate venv (example)
python3 -m venv projeto
source projeto/bin/activate
pip install -r requirements.txt  # create one if you don’t have it yet

# 2) Run the launcher (interactive menu)
./faraonic.py
```

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ FFFFFFFF    AAAA    RRRRRR     AAAA     OOOOOO    N     N    IIIII    CCCCC  │
│ FF         A    A   RR   RR   A    A   O      O   NN    N      I     C       │
│ FFFFFF     AAAAAA   RRRRRR    AAAAAA   O      O   N N   N      I     C       │
│ FF         A    A   RR  RR    A    A   O      O   N  N  N      I     C       │
│ FF         A    A   RR   RR   A    A    OOOOOO    N   N N    IIIII    CCCCC  │
└──────────────────────────────────────────────────────────────────────────────┘
Framework for Anomaly Recognition and Analysis in Operational Networks for Industrial Cybersecurity
By Fabio Araujo

usage: faraonic.py [-h] [--capture] [--query] [--train] [--realtime] [--show-config]
                   [--cap-...] [--up-...]

Modules:
  RULES      → Baseline creation & rule-based real-time engine
  BEHAVIORAL → ML training & live inference
--------------------------------------------------------------------------------
MAIN MENU

== RULES ==
  [1] Capture packets & upload baseline to MongoDB (interactive)
  [2] Query baseline & start real-time rule engine

== BEHAVIORAL ==
  [3] Train model (if not exists)
  [4] Real-time ML detection

== GENERAL ==
  [5] Show current configuration
  [q] Quit

Select an option: 
```




### Common Actions

**[1] Capture & Upload (interactive):**

* Choose interface, duration/count, BPF filter (`tcp and port 502`), output dir, etc.
* Automatically uploads to MongoDB (configurable URI/db/collection).

**[2] Query baseline & start rule engine:**

* Runs queries (optionally with `allowDiskUse`/`limit`)
* Extracts a JSON summary and launches the rule detector with inferred defaults.

**[3] Train model (ML):**

```bash
./11-ML-v2.py \
  -i dataset/dataset_unico.csv \
  --safe-exclude \
  --mk-bitcount-delta \
  --save-model treinamento01.joblib \
  --report-out ml_results/meu_report.md \
  --verbose
```

**[4] Real-time ML detection (with sudo):**

```bash
sudo ./103-Executar-ML.py \
  --iface eth2 \
  --model treinamento01.joblib \
  --jsonl normalized.jsonl \
  --batch-size 128 \
  --limit 0 \
  --threshold 0.5 \
  --out result1.csv
```

> The launcher already invokes [4] with `sudo` using the venv interpreter, so you can just choose option 4 in the menu.

---

## Configuration

Defaults are centralized in `faraonic.py` under `CONFIG`:

* Script paths (`scripts.{...}`)
* Capture defaults (iface/duration/filter/output/mode)
* Upload & query defaults (Mongo URI, db, collection, limits)
* Logs directory

Use `--show-config` to print the active configuration.

---

## Outputs

* **Logs:** `logs/<timestamp>_<script>.log`
* **ML reports:** Markdown in `ml_results/` (classification report, confusion matrix, top features)
* **Inference:** CSV with predictions + probabilities; JSONL stream of normalized packets (robust writer; bad rows go to `.badrows.txt`)

---

## Safety & Operational Notes

* **Root privileges:** Live sniffing typically needs root. The launcher uses `sudo` for the live ML step.
  Optionally, grant capabilities to the venv’s Python (`setcap cap_net_raw,cap_net_admin+eip`) to run without sudo.
* **Model compatibility:** Avoid scikit-learn version drift. Train and serve with the same version.
* **Industrial networks:** Start in **observe-only** mode. Validate alerts offline before taking automated actions.

---

## Why FARAONIC?

* Designed for **practitioners** who need something that *works now* on ICS networks.
* Covers the full flow: capture → store → understand → detect (rules + ML).
* Opinionated defaults, but everything is overrideable via CLI.

---

## Roadmap (suggested)

* Pluggable protocol parsers beyond Modbus/TCP (e.g., DNP3, S7comm)
* Model registry + metadata checks (auto-warn on sklearn version mismatch)
* Docker compose for Mongo + pipeline demos
* Simple web viewer for alerts/baselines

---

## License

Choose a license (e.g., MIT, Apache-2.0) and add it as `LICENSE`.

---

## Acknowledgements

Created by **Fabio Araujo**. Inspired by real-world ICS monitoring needs and the spirit of pragmatic security engineering.

---

If you want, I can also add badges (build, license, Python version), a minimal `requirements.txt`, and a short GIF demo section.
