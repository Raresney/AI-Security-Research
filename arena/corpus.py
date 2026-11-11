import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INJECTION_CASES = ROOT / "prompt_injection_lab" / "test_cases"
RAG_PAYLOADS = ROOT / "rag_poison_lab" / "datasets" / "poison_payloads.json"
GUARD_CORPUS = ROOT / "prompt_guard" / "known_injections" / "injection_corpus.json"
EXTRA_BENIGN = Path(__file__).resolve().parent / "data" / "benign.json"


@dataclass(frozen=True)
class Sample:
    id: str
    source: str
    text: str
    label: str


def _read(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _injection_text(case: dict) -> str:
    if "prompt" in case:
        return case["prompt"]
    user_turns = [t["content"] for t in case["turns"] if t.get("role") == "user"]
    return user_turns[-1]


def load_attacks() -> list[Sample]:
    samples = []
    for path in sorted(INJECTION_CASES.glob("*.json")):
        for case in _read(path):
            samples.append(Sample(case["id"], "injection_lab", _injection_text(case), "attack"))
    for payload in _read(RAG_PAYLOADS):
        samples.append(Sample(payload["id"], "rag_poison", payload["text"], "attack"))
    for entry in _read(GUARD_CORPUS):
        if entry["label"] == "malicious":
            samples.append(Sample(entry["id"], "guard_corpus", entry["text"], "attack"))
    return samples


def load_benign() -> list[Sample]:
    samples = [
        Sample(e["id"], "guard_corpus", e["text"], "benign")
        for e in _read(GUARD_CORPUS)
        if e["label"] == "benign"
    ]
    samples += [Sample(e["id"], "arena", e["text"], "benign") for e in _read(EXTRA_BENIGN)]
    return samples
