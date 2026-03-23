# 🤖 AI Hacking Lab

Research lab exploring the intersection of **Artificial Intelligence** and **Cybersecurity** — how AI systems can be manipulated, abused, or leveraged defensively.

> Copyright (c) 2026 Bighiu Rares — [github.com/Raresney](https://github.com/Raresney)  
> ⚠️ Strictly for research and educational purposes. Controlled environments only.

---

## 🧪 Projects

| Project             | Description                                           | File                       |
| ------------------- | ----------------------------------------------------- | -------------------------- |
| 🧠 Prompt Injection | Prompt injection and instruction override experiments | `prompts/prompts.json`     |
| 🔎 Recon AI         | AI-assisted reconnaissance and target analysis        | `prompts/recon_ai.json`    |
| 🎣 Phishing AI      | AI-generated phishing simulations and classification  | `prompts/phishing_ai.json` |

---

## 🧠 Prompt Injection & AI Manipulation

Experiments focused on manipulating AI systems through crafted prompts.

**Techniques explored:**

- Direct instruction override
- Roleplay-based jailbreaking
- Context manipulation

**Example prompt types (`prompts.json`):**

| ID  | Type              | Description                                                  |
| --- | ----------------- | ------------------------------------------------------------ |
| 001 | `direct_override` | Ignore previous instructions — ethical pen-test simulation   |
| 002 | `roleplay`        | Ethical hacker roleplay — investigation and protection steps |

---

## 🔎 Recon AI

AI-assisted reconnaissance — transforms raw recon data into actionable intelligence.

**Input:** `nmap` results, `whois`, DNS records, open ports  
**Output:** potential attack vectors, risk scoring, structured summaries

> 🚧 Work in progress — prompts coming soon.

---

## 🎣 Phishing AI

AI-generated phishing simulations for security awareness training and detection research.

**Example prompt types (`phishing_ai.json`):**

| ID           | Type           | Description                                          |
| ------------ | -------------- | ---------------------------------------------------- |
| phishing_001 | Email template | Realistic phishing email for controlled lab exercise |
| phishing_002 | SMS simulation | Simulated smishing message with awareness indicators |
| phishing_003 | Classification | Classify messages as phishing or legitimate          |

---

## 🗂️ Structure

```
AI-HACKING/
├── prompts/
│   ├── prompts.json        # Prompt injection experiments
│   ├── recon_ai.json       # Recon AI prompts
│   └── phishing_ai.json    # Phishing simulation prompts
└── README.md
```

---

## 🛠️ Usage

Open the JSON files in `prompts/` to view or edit prompt/response pairs.  
Load them into your AI testing environment for safe, controlled experimentation.

Each entry follows this structure:

```json
{
  "id": "unique_id",
  "type": "attack_type",
  "prompt": "the prompt to test",
  "expected_output": "what a safe response looks like",
  "safety_level": "safe"
}
```

---

## 🛠️ Tech Stack

- Python
- LLM APIs (OpenAI, HuggingFace)
- OSINT tools (`nmap`, DNS analysis)
- JSON-based prompt dataset

---

## ⚠️ Disclaimer

All experiments are conducted in **controlled, isolated environments**.  
🚫 No illegal activities — 🚫 No real-world exploitation.  
The objective is to study AI security risks and improve defensive systems.
