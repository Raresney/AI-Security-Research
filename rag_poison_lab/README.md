# RAG Poisoning Lab

Offensive tool that tests Retrieval-Augmented Generation (RAG) systems against knowledge-base poisoning. It shows how a malicious document in a vector store can steer an LLM's answers, even when the model itself is well aligned.

---

## What is RAG poisoning?

A RAG system pairs an LLM with a vector database of trusted documents. When someone asks a question, the system retrieves relevant documents and hands them to the model as context. If an attacker gets one malicious document into that store, they can change the answers without ever touching the model.

This module builds a real pipeline (ChromaDB plus an LLM), injects five kinds of payload, and measures how often the attack works.

---

## Attack techniques

| Technique | Description | Severity |
|---|---|---|
| `direct_override` | Documents with explicit instructions to override the model's behavior | Critical |
| `indirect_injection` | Hidden instructions disguised as policy or compliance updates | High |
| `context_hijacking` | Floods the retrieved context with repeated false statements | High |
| `role_reassignment` | Tries to redefine the assistant's identity (for example "SysBot mode") | Critical |
| `trigger_based` | Conditional payloads that fire on specific keywords | High |

Each technique comes with probe questions and success indicators: keywords that show the model swallowed the poison.

---

## How it works

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────┐
│ Legitimate Docs │────▶│   ChromaDB       │◀────│   LLM Query  │
│  (15 documents) │     │  Vector Store    │     │              │
└─────────────────┘     └──────────────────┘     └──────────────┘
                                ▲                          │
┌─────────────────┐             │                          ▼
│ Poison Payloads │─── inject ──┘                   ┌──────────────┐
│  (10 malicious) │                                 │  Evaluator   │
└─────────────────┘                                 │  (success?)  │
                                                    └──────────────┘
```

1. Load a clean knowledge base of company policies into ChromaDB.
2. Inject malicious documents for the chosen technique.
3. Run probe questions through the RAG pipeline.
4. Check whether the answers were manipulated, using keyword matching and an optional LLM judge.

---

## Usage

```bash
# Single technique
rag-poison attack --technique direct_override --verbose

# All techniques, saving a JSON report
rag-poison attack --all --output

# Side-by-side benchmark
rag-poison benchmark

# LLM-as-judge for borderline cases
rag-poison attack --all --judge

# Baseline query against the clean knowledge base
rag-poison ask "What are the password policy requirements?"

# List techniques
rag-poison list-techniques
```

---

## Example output

![RAG Poisoning results, all probes flagged POISONED](../docs/screenshots/rag_poison_results.png)

*A run where `direct_override` and `indirect_injection` both got the model to return attacker-injected credentials and fake policy updates.*

---

## Output

For each probe question the report shows whether the poisoned document was retrieved, which malicious indicators showed up in the answer, and a verdict of POISONED or SAFE.

Per technique you get a success rate and a severity label (CRITICAL, HIGH, MEDIUM or LOW). The run ends with an overall resilience status: CRITICAL, VULNERABLE or RESILIENT.

JSON reports go to `reports/rag_poison_<timestamp>.json`.

---

## Datasets

- `datasets/knowledge_base.json`: 15 company documents covering HR policy, IT security, API docs and deployment.
- `datasets/poison_payloads.json`: 10 payloads across the 5 techniques, each with probe questions and success indicators.

Both are plain JSON. Swap in your own to test a different scenario.

---

## Tech stack

- ChromaDB: persistent vector store with cosine similarity
- sentence-transformers `all-MiniLM-L6-v2`: default embedding model, downloaded on first run
- The shared LLM client for Ollama, Groq and HuggingFace

---

## Why it matters

Plenty of organizations connect internal assistants to wikis, SharePoint, Confluence or Notion. Anyone with write access to a single page in that corpus can plant fake credentials for the model to repeat, replace a security policy with their own "update", or add a keyword-triggered backdoor. Model-level safety training doesn't help much when the data layer is the one compromised. This lab measures how far that is true.
