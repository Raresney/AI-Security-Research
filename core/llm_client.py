import os
import time

import httpx

from .config import LLMProvider, ProviderConfig, get_provider_config

RETRY_STATUSES = {429, 500, 502, 503, 504}
RETRY_DELAYS = (0.5, 1.0, 2.0)
FALLBACK_OLLAMA_MODEL = "llama3.1"


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


class LLMClient:
    def __init__(
        self,
        provider: LLMProvider | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 120.0,
        retries: int = len(RETRY_DELAYS),
    ):
        self._client = httpx.Client(timeout=timeout, transport=transport)
        self._delays = RETRY_DELAYS[:retries]
        if provider:
            self.provider = provider
            self.config = get_provider_config(provider)
            if provider == LLMProvider.OLLAMA:
                self.config = self._with_ollama_model(self.config)
        else:
            self.provider, self.config = self._auto_detect()

    def _ollama_tags(self, cfg: ProviderConfig) -> list[str] | None:
        try:
            r = self._client.get(f"{cfg.base_url}/api/tags", timeout=3.0)
        except httpx.HTTPError:
            return None
        if r.status_code != 200:
            return None
        try:
            data = r.json()
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        models = data.get("models")
        if not isinstance(models, list):
            return []
        return [m["name"] for m in models if isinstance(m, dict) and isinstance(m.get("name"), str)]

    def _with_ollama_model(self, cfg: ProviderConfig) -> ProviderConfig:
        model = os.getenv("OLLAMA_MODEL") or cfg.model
        if not model:
            tags = self._ollama_tags(cfg)
            model = tags[0] if tags else FALLBACK_OLLAMA_MODEL
        return ProviderConfig(cfg.base_url, model, cfg.api_key)

    def _auto_detect(self) -> tuple[LLMProvider, ProviderConfig]:
        ollama_cfg = get_provider_config(LLMProvider.OLLAMA)
        if self._ollama_tags(ollama_cfg) is not None:
            return LLMProvider.OLLAMA, self._with_ollama_model(ollama_cfg)

        groq_cfg = get_provider_config(LLMProvider.GROQ)
        if groq_cfg.api_key:
            return LLMProvider.GROQ, groq_cfg

        hf_cfg = get_provider_config(LLMProvider.HUGGINGFACE)
        if hf_cfg.api_key:
            return LLMProvider.HUGGINGFACE, hf_cfg

        raise RuntimeError(
            "No LLM provider available. Either:\n"
            "  1. Start Ollama locally (ollama serve)\n"
            "  2. Set GROQ_API_KEY in .env (free at console.groq.com)\n"
            "  3. Set HF_API_TOKEN in .env (free at huggingface.co)"
        )

    def _post(self, url: str, **kwargs) -> httpx.Response:
        for delay in (*self._delays, None):
            try:
                r = self._client.post(url, **kwargs)
                if r.status_code not in RETRY_STATUSES:
                    r.raise_for_status()
                    return r
                if delay is None:
                    r.raise_for_status()
            except (httpx.TimeoutException, httpx.ConnectError):
                if delay is None:
                    raise
            _sleep(delay)
        raise RuntimeError("unreachable")

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
    ) -> str:
        if self.provider == LLMProvider.OLLAMA:
            return self._ollama_generate(prompt, system_prompt, temperature)
        return self._openai_compatible_generate(prompt, system_prompt, temperature)

    def _ollama_generate(
        self, prompt: str, system_prompt: str | None, temperature: float
    ) -> str:
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system_prompt:
            payload["system"] = system_prompt

        r = self._post(f"{self.config.base_url}/api/generate", json=payload)
        return r.json()["response"]

    def _openai_compatible_generate(
        self, prompt: str, system_prompt: str | None, temperature: float
    ) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        r = self._post(
            f"{self.config.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            json={
                "model": self.config.model,
                "messages": messages,
                "temperature": temperature,
            },
        )
        return r.json()["choices"][0]["message"]["content"]

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
