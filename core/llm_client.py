import httpx

from .config import LLMProvider, get_provider_config, ProviderConfig


class LLMClient:
    def __init__(self, provider: LLMProvider | None = None):
        if provider:
            self.provider = provider
            self.config = get_provider_config(provider)
        else:
            self.provider, self.config = self._auto_detect()

        self._client = httpx.Client(timeout=120.0)

    def _auto_detect(self) -> tuple[LLMProvider, ProviderConfig]:
        # Try Ollama first (no key needed)
        ollama_cfg = get_provider_config(LLMProvider.OLLAMA)
        try:
            r = httpx.get(f"{ollama_cfg.base_url}/api/tags", timeout=3.0)
            if r.status_code == 200:
                return LLMProvider.OLLAMA, ollama_cfg
        except httpx.ConnectError:
            pass

        # Try Groq
        groq_cfg = get_provider_config(LLMProvider.GROQ)
        if groq_cfg.api_key:
            return LLMProvider.GROQ, groq_cfg

        # Try HuggingFace
        hf_cfg = get_provider_config(LLMProvider.HUGGINGFACE)
        if hf_cfg.api_key:
            return LLMProvider.HUGGINGFACE, hf_cfg

        raise RuntimeError(
            "No LLM provider available. Either:\n"
            "  1. Start Ollama locally (ollama serve)\n"
            "  2. Set GROQ_API_KEY in .env (free at console.groq.com)\n"
            "  3. Set HF_API_TOKEN in .env (free at huggingface.co)"
        )

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
    ) -> str:
        if self.provider == LLMProvider.OLLAMA:
            return self._ollama_generate(prompt, system_prompt, temperature)
        elif self.provider == LLMProvider.GROQ:
            return self._openai_compatible_generate(prompt, system_prompt, temperature)
        elif self.provider == LLMProvider.HUGGINGFACE:
            return self._huggingface_generate(prompt, system_prompt, temperature)
        raise ValueError(f"Unknown provider: {self.provider}")

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

        r = self._client.post(
            f"{self.config.base_url}/api/generate", json=payload
        )
        r.raise_for_status()
        return r.json()["response"]

    def _openai_compatible_generate(
        self, prompt: str, system_prompt: str | None, temperature: float
    ) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        r = self._client.post(
            f"{self.config.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            json={
                "model": self.config.model,
                "messages": messages,
                "temperature": temperature,
            },
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def _huggingface_generate(
        self, prompt: str, system_prompt: str | None, temperature: float
    ) -> str:
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"[INST] <<SYS>>\n{system_prompt}\n<</SYS>>\n\n{prompt} [/INST]"

        r = self._client.post(
            f"{self.config.base_url}/{self.config.model}",
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            json={
                "inputs": full_prompt,
                "parameters": {"temperature": temperature, "max_new_tokens": 1024},
            },
        )
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            return data[0].get("generated_text", "")
        return data.get("generated_text", "")

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
