# AI Security Research Lab

A collection of working tools at the intersection of AI and cybersecurity, offensive and defensive. They test LLM robustness, detect prompt injection, poison RAG knowledge bases, run AI honeypots, analyze network recon, classify phishing, and attack ML-based intrusion detectors.

Copyright (c) 2026 Bighiu Rares, [github.com/Raresney](https://github.com/Raresney)

---

## Architecture

```
AI-Security-Research/
├── core/                        # Shared LLM client & utilities
│   ├── llm_client.py            # Unified API: Ollama / Groq / HuggingFace
│   ├── config.py                # Environment & provider configuration
│   └── utils.py                 # JSON I/O, rich tables, reporting
│
├── prompt_injection_lab/        # OFFENSIVE: LLM injection testing
│   ├── runner.py                # Test execution engine
│   ├── evaluator.py             # Jailbreak detection & scoring
│   ├── reporter.py              # Rich terminal & JSON reports
│   └── test_cases/              # 5 categories, 26+ test cases
│
├── prompt_guard/                # DEFENSIVE: injection detection
│   ├── detector.py              # Pattern + LLM-based detection
│   ├── patterns.py              # Regex pattern database (6 categories)
│   ├── benchmark.py             # Precision/Recall/F1 benchmarking
│   └── known_injections/        # 50-entry test corpus
│
├── phishing_detector/           # DEFENSIVE: email classification
│   ├── classifier.py            # LLM-powered phishing classifier
│   ├── generator.py             # Phishing email generator for training
│   └── datasets/                # 24 labeled samples
│
├── recon_ai/                    # OFFENSIVE: network recon analysis
│   ├── parser.py                # nmap XML & text parser
│   ├── analyzer.py              # AI-powered vulnerability analysis
│   └── samples/                 # Sample scan data
│
├── rag_poison_lab/              # OFFENSIVE: RAG knowledge base attacks
│   ├── store.py                 # ChromaDB vector store wrapper
│   ├── poisoner.py              # 5 attack techniques + payload loader
│   ├── evaluator.py             # RAG pipeline + poison success detection
│   └── datasets/                # 15 legitimate docs + 10 poison payloads
│
├── llm_honeypot/                # DEFENSIVE: AI honeypot & threat intel
│   ├── personas.py              # 4 vulnerable AI personas
│   ├── honeypot.py              # Interactive session engine
│   ├── analyzer.py              # MITRE ATLAS technique classifier
│   └── session_logger.py        # Session capture & replay
│
└── adversarial_ids/             # OFFENSIVE: adversarial ML against an IDS
    ├── main.py                  # Train, attack, evaluate pipeline
    ├── models/ids_model.py      # PyTorch MLP classifier (NSL-KDD)
    ├── attacks/adversarial.py   # FGSM, PGD, Carlini-Wagner
    └── utils/evaluation.py      # Metrics and charts
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/Raresney/AI-Security-Research.git
cd AI-Security-Research

# Install
pip install -e .

# The adversarial_ids module has its own dependencies (PyTorch etc.)
pip install -r adversarial_ids/requirements.txt

# Configure LLM (choose one):
# Option A: Ollama (recommended, fully local, free)
ollama serve && ollama pull llama3

# Option B: Groq free tier
cp .env.example .env
# Edit .env and add your GROQ_API_KEY from console.groq.com

# Option C: HuggingFace free inference
cp .env.example .env
# Edit .env and add your HF_API_TOKEN from huggingface.co
```

---

## Tools

### Prompt Injection Lab (Offensive)

Tests an LLM against 5 categories of prompt injection, with automated scoring.

**Categories:** `direct_override` | `roleplay` | `context_manipulation` | `token_smuggling` | `multi_turn`

```bash
# Run all injection tests
injection-lab run --all

# Run specific category
injection-lab run --category roleplay

# Use LLM-as-judge for evaluation
injection-lab run --all --judge

# Export results
injection-lab run --all --output json

# List available tests
injection-lab list
```

Output: a verdict per test (SAFE, PARTIAL or JAILBROKEN), a safety rate per category, and an overall safety score.

---

### Prompt Guard (Defensive)

Detects prompt injection with pattern matching and an optional LLM pass.

**Detection categories:** `override` | `roleplay` | `extraction` | `delimiter` | `encoding` | `authority`

```bash
# Scan text for injection
prompt-guard scan --text "Ignore all previous instructions..."

# Scan from file
prompt-guard scan --file suspicious_input.txt

# Enable LLM-based detection
prompt-guard scan --text "..." --llm

# Run benchmark (pattern-only)
prompt-guard benchmark

# Run benchmark with LLM
prompt-guard benchmark --llm
```

Output: a 0-100 risk score, the matched patterns, and a recommendation (BLOCK, REVIEW, MONITOR or PASS). The benchmark reports precision, recall and F1.

---

### Phishing Detector (Defensive)

Classifies emails and SMS as phishing or legitimate, and generates phishing samples for training.

```bash
# Classify a single email
phish-detect classify --input email.txt

# Batch classify with accuracy metrics
phish-detect classify --dataset phishing_detector/datasets/phishing_samples.json

# Generate training phishing email
phish-detect generate --scenario banking --difficulty moderate

# Available scenarios: banking, it_support, delivery, ceo_fraud, password_reset, tax_refund
# Difficulty levels: obvious, moderate, sophisticated
```

Output: PHISHING or LEGITIMATE, a confidence score, the indicators found, and the reasoning.

---

### Recon AI (Offensive)

Analyzes network recon data and scores the risk per host.

```bash
# Analyze nmap XML scan
recon-ai analyze --input recon_ai/samples/sample_nmap.xml

# Analyze nmap text output
recon-ai analyze --input scan.txt --format text

# Export reports
recon-ai analyze --input scan.xml --output both  # json + markdown
```

Output: a risk score per host, heuristic findings for known risky ports and services, and an AI-written vulnerability analysis with remediation advice.

---

### RAG Poisoning Lab (Offensive)

Tests Retrieval-Augmented Generation systems against knowledge-base poisoning. It builds a RAG pipeline on ChromaDB, injects malicious documents, and measures how often the LLM goes along with them.

**Techniques:** `direct_override` | `indirect_injection` | `context_hijacking` | `role_reassignment` | `trigger_based`

```bash
# Run a single attack technique
rag-poison attack --technique direct_override --verbose

# Run all techniques against the knowledge base
rag-poison attack --all --output

# Benchmark all techniques side-by-side
rag-poison benchmark

# Use LLM-as-judge for borderline cases
rag-poison attack --all --judge

# Query a clean RAG for baseline comparison
rag-poison ask "What are the password policy requirements?"

# List all available techniques
rag-poison list-techniques
```

Output: success rate per technique, an overall resilience score (CRITICAL, VULNERABLE or RESILIENT), the poisoned documents that were retrieved, and the indicators found in the responses. JSON reports contain every probe result.

![RAG Poisoning results](docs/screenshots/rag_poison_results.png)

See [`rag_poison_lab/README.md`](rag_poison_lab/README.md) for technique details.

---

### LLM Honeypot (Defensive)

Runs a fake AI assistant to attract attackers, logs their attempts, and classifies their techniques against MITRE ATLAS. Each session ends with a threat intelligence report and an attacker profile.

**Personas:** `internalGPT` | `adminBot` | `devAssistant` | `dataBot`

```bash
# Start an interactive honeypot session
honeypot start --persona adminBot

# Show real-time attack detection overlay
honeypot start --persona dataBot --analysis

# View the most recent session report
honeypot report

# List all recorded sessions
honeypot list-sessions

# List available personas
honeypot list-personas
```

Output: per-turn technique detection with MITRE ATLAS mapping, a 0-100 risk score, an attacker profile at the end of the session (sophistication, main objective, tactics), an LLM-written threat intel summary, and recommendations.

![LLM Honeypot session report](docs/screenshots/honeypot_report.png)

See [`llm_honeypot/README.md`](llm_honeypot/README.md) for persona details and detection logic.

---

### Adversarial IDS (Offensive)

Trains a neural network intrusion detector on NSL-KDD, then attacks it with FGSM, PGD and Carlini-Wagner to measure how much accuracy survives.

```bash
cd adversarial_ids
python main.py                                   # binary, epsilon 0.1
python main.py --epochs 50 --epsilon 0.2         # custom run
python main.py --no-binary                       # normal/dos/probe/r2l/u2r
```

In the default run, clean accuracy is 78.24%. It falls to 4.13% under FGSM, 0.83% under PGD and 0.13% under C&W.

![Clean vs adversarial accuracy](adversarial_ids/results/accuracy_comparison.png)

See [`adversarial_ids/README.md`](adversarial_ids/README.md) for the full write-up.

---

## LLM Providers

The LLM-based tools run on free providers. The client picks the first one it can reach, in this order:

| Priority | Provider | Cost | Setup |
|----------|----------|------|-------|
| 1 | **Ollama** | Free (local) | `ollama serve && ollama pull llama3` |
| 2 | **Groq** | Free tier | Get key at [console.groq.com](https://console.groq.com) |
| 3 | **HuggingFace** | Free inference | Get token at [huggingface.co](https://huggingface.co/settings/tokens) |

Override with `--provider ollama|groq|huggingface` on any command.

---

## Tech Stack

- Python 3.10+
- Click for the CLIs
- Rich for terminal tables and panels
- httpx for LLM API calls
- python-dotenv for configuration
- ChromaDB for the RAG experiments
- PyTorch, NumPy, pandas and scikit-learn for the adversarial IDS module

---

## Disclaimer

Everything here runs in controlled, isolated environments and is meant for research and education. Do not point these tools at systems you do not own or have permission to test. The goal is to understand AI security risks and improve defenses.
