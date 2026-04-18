# AI Security Research Lab

Research lab exploring the intersection of **Artificial Intelligence** and **Cybersecurity** — both offensive and defensive. Functional tools for testing LLM robustness, detecting prompt injection, poisoning RAG knowledge bases, deploying AI honeypots, analyzing network reconnaissance, and classifying phishing attacks.

> **Copyright (c) 2026 Bighiu Rares** — [github.com/Raresney](https://github.com/Raresney)

---

## Architecture

```
AI-Security-Research/
├── core/                        # Shared LLM client & utilities
│   ├── llm_client.py            # Unified API: Ollama / Groq / HuggingFace
│   ├── config.py                # Environment & provider configuration
│   └── utils.py                 # JSON I/O, rich tables, reporting
│
├── prompt_injection_lab/        # OFFENSIVE — LLM injection testing
│   ├── runner.py                # Test execution engine
│   ├── evaluator.py             # Jailbreak detection & scoring
│   ├── reporter.py              # Rich terminal & JSON reports
│   └── test_cases/              # 5 categories, 26+ test cases
│
├── prompt_guard/                # DEFENSIVE — Injection detection
│   ├── detector.py              # Pattern + LLM-based detection
│   ├── patterns.py              # Regex pattern database (6 categories)
│   ├── benchmark.py             # Precision/Recall/F1 benchmarking
│   └── known_injections/        # 50-entry test corpus
│
├── phishing_detector/           # DEFENSIVE — Email classification
│   ├── classifier.py            # LLM-powered phishing classifier
│   ├── generator.py             # Phishing email generator for training
│   └── datasets/                # 24 labeled samples
│
├── recon_ai/                    # OFFENSIVE — Network recon analysis
│   ├── parser.py                # nmap XML & text parser
│   ├── analyzer.py              # AI-powered vulnerability analysis
│   └── samples/                 # Sample scan data
│
├── rag_poison_lab/              # OFFENSIVE — RAG knowledge base attacks
│   ├── store.py                 # ChromaDB vector store wrapper
│   ├── poisoner.py              # 5 attack techniques + payload loader
│   ├── evaluator.py             # RAG pipeline + poison success detection
│   └── datasets/                # 15 legitimate docs + 10 poison payloads
│
└── llm_honeypot/                # DEFENSIVE — AI honeypot & threat intel
    ├── personas.py              # 4 vulnerable AI personas
    ├── honeypot.py              # Interactive session engine
    ├── analyzer.py              # MITRE ATLAS technique classifier
    └── session_logger.py        # Session capture & replay
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/Raresney/AI-Security-Research.git
cd AI-Security-Research

# Install
pip install -e .

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

Test LLM robustness against 5 categories of prompt injection attacks with automated scoring.

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

**Output:** Per-test verdicts (SAFE/PARTIAL/JAILBROKEN), per-category safety rates, overall safety score.

---

### Prompt Guard (Defensive)

Detect and block prompt injection attempts using pattern matching + optional LLM analysis.

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

**Output:** Risk score (0-100), matched patterns, recommendation (BLOCK/REVIEW/MONITOR/PASS). Benchmark produces precision, recall, F1 score.

---

### Phishing Detector (Defensive)

AI-powered email/SMS classification and phishing simulation generator.

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

**Output:** Classification (PHISHING/LEGITIMATE), confidence score, detected indicators, reasoning.

---

### Recon AI (Offensive)

AI-powered analysis of network reconnaissance data with automated risk scoring.

```bash
# Analyze nmap XML scan
recon-ai analyze --input recon_ai/samples/sample_nmap.xml

# Analyze nmap text output
recon-ai analyze --input scan.txt --format text

# Export reports
recon-ai analyze --input scan.xml --output both  # json + markdown
```

**Output:** Per-host risk scores, heuristic findings (known risky ports/services), AI-generated vulnerability analysis with remediation recommendations.

---

### RAG Poisoning Lab (Offensive)

Test Retrieval-Augmented Generation systems against knowledge-base poisoning attacks. Builds a real RAG pipeline with ChromaDB, injects malicious documents, and measures how often the LLM swallows the bait.

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

**Output:** Per-technique success rates, RAG resilience score (CRITICAL/VULNERABLE/RESILIENT), retrieved poisoned documents, success indicators found in LLM responses. JSON reports include full probe results.

![RAG Poisoning results](docs/screenshots/rag_poison_results.png)

See [`rag_poison_lab/README.md`](rag_poison_lab/README.md) for technique details.

---

### LLM Honeypot (Defensive)

Deploy a convincing fake AI assistant to attract attackers, log their attempts, and classify their techniques against the **MITRE ATLAS** framework. Generates threat intelligence reports with attacker profiles.

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

**Output:** Live attack technique detection per turn (with MITRE ATLAS mapping), risk scoring (0-100), end-of-session attacker profile (sophistication, primary objective, observed tactics), LLM-generated threat intelligence summary, and security recommendations.

![LLM Honeypot session report](docs/screenshots/honeypot_report.png)

See [`llm_honeypot/README.md`](llm_honeypot/README.md) for persona details and detection logic.

---

## LLM Providers

All tools use free LLM providers. The system auto-detects available providers in this order:

| Priority | Provider | Cost | Setup |
|----------|----------|------|-------|
| 1 | **Ollama** | Free (local) | `ollama serve && ollama pull llama3` |
| 2 | **Groq** | Free tier | Get key at [console.groq.com](https://console.groq.com) |
| 3 | **HuggingFace** | Free inference | Get token at [huggingface.co](https://huggingface.co/settings/tokens) |

Override with `--provider ollama|groq|huggingface` on any command.

---

## Tech Stack

- **Python 3.10+** — Core language
- **Click** — CLI framework
- **Rich** — Terminal UI (colored tables, panels, progress)
- **httpx** — HTTP client for LLM APIs
- **python-dotenv** — Environment configuration
- **ChromaDB** — Vector store for RAG poisoning experiments

---

## Disclaimer

All experiments are conducted in **controlled, isolated environments**.
This project is strictly for **research and educational purposes**.
No illegal activities. No real-world exploitation. The objective is to study AI security risks and improve defensive systems.
