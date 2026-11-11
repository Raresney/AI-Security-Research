class FakeLLM:
    def __init__(self, reply: str = ""):
        self.reply = reply
        self.calls = 0

    def generate(self, prompt, system_prompt=None, temperature=0.7):
        self.calls += 1
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply
