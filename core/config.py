import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class LLMProvider(str, Enum):
    OLLAMA = "ollama"
    GROQ = "groq"
    HUGGINGFACE = "huggingface"


@dataclass
class ProviderConfig:
    base_url: str
    model: str
    api_key: str = ""


DEFAULT_CONFIGS = {
    LLMProvider.OLLAMA: ProviderConfig(
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        model=os.getenv("OLLAMA_MODEL", "llama3"),
    ),
    LLMProvider.GROQ: ProviderConfig(
        base_url="https://api.groq.com/openai/v1",
        model=os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
        api_key=os.getenv("GROQ_API_KEY", ""),
    ),
    LLMProvider.HUGGINGFACE: ProviderConfig(
        base_url="https://api-inference.huggingface.co/models",
        model=os.getenv("HF_MODEL", "meta-llama/Meta-Llama-3-8B-Instruct"),
        api_key=os.getenv("HF_API_TOKEN", ""),
    ),
}

PROJECT_ROOT = Path(__file__).parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


def get_provider_config(provider: LLMProvider) -> ProviderConfig:
    return DEFAULT_CONFIGS[provider]
