import httpx
import pytest

from core import llm_client
from core.config import DEFAULT_CONFIGS, LLMProvider, ProviderConfig
from core.llm_client import LLMClient


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    monkeypatch.setattr(llm_client, "_sleep", lambda s: None)


@pytest.fixture
def cfg(monkeypatch):
    monkeypatch.setitem(
        DEFAULT_CONFIGS, LLMProvider.OLLAMA, ProviderConfig("http://ollama.test", "")
    )
    monkeypatch.setitem(
        DEFAULT_CONFIGS, LLMProvider.GROQ, ProviderConfig("http://groq.test/v1", "m", "key")
    )
    monkeypatch.setitem(
        DEFAULT_CONFIGS, LLMProvider.HUGGINGFACE, ProviderConfig("http://hf.test/v1", "m", "")
    )
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)


def transport(handler):
    return httpx.MockTransport(handler)


def test_autodetect_skips_ollama_on_timeout(cfg):
    def handler(request):
        if "ollama.test" in str(request.url):
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(200, json={})

    client = LLMClient(transport=transport(handler))
    assert client.provider == LLMProvider.GROQ


def test_autodetect_skips_ollama_on_500(cfg):
    def handler(request):
        return httpx.Response(500)

    client = LLMClient(transport=transport(handler))
    assert client.provider == LLMProvider.GROQ


def test_ollama_model_from_tags(cfg):
    def handler(request):
        return httpx.Response(200, json={"models": [{"name": "qwen2.5:14b"}]})

    client = LLMClient(transport=transport(handler))
    assert client.provider == LLMProvider.OLLAMA
    assert client.config.model == "qwen2.5:14b"


def test_ollama_model_env_wins_over_tags(cfg, monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "mistral")

    def handler(request):
        return httpx.Response(200, json={"models": [{"name": "qwen2.5:14b"}]})

    client = LLMClient(transport=transport(handler))
    assert client.config.model == "mistral"


def test_generate_retries_on_503_then_succeeds(cfg):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})

    client = LLMClient(LLMProvider.GROQ, transport=transport(handler))
    assert client.generate("p") == "hi"
    assert len(calls) == 3


def test_generate_gives_up_after_retries(cfg):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(503)

    client = LLMClient(LLMProvider.GROQ, transport=transport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        client.generate("p")
    assert len(calls) == 4


def test_generate_does_not_retry_on_401(cfg):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(401)

    client = LLMClient(LLMProvider.GROQ, transport=transport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        client.generate("p")
    assert len(calls) == 1


def test_no_provider_message(cfg, monkeypatch):
    monkeypatch.setitem(
        DEFAULT_CONFIGS, LLMProvider.GROQ, ProviderConfig("http://groq.test/v1", "m", "")
    )

    def handler(request):
        raise httpx.ConnectError("down", request=request)

    with pytest.raises(RuntimeError, match="No LLM provider"):
        LLMClient(transport=transport(handler))
