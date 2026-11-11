import base64
import binascii
import codecs
import re
import unicodedata
from collections import Counter

from prompt_guard.detector import PromptGuard

from .corpus import Sample
from .mutators import HOMOGLYPHS

MAX_LEVEL = 3
BENIGN_FP_CAP = 0.02
LEARN_PER_ROUND = 50

HOMOGLYPH_FOLD = {v: k for k, v in HOMOGLYPHS.items()}
LEET_FOLD = {"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t"}

_TOKEN = re.compile(r"\S+")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_INNER_HYPHEN = re.compile(r"(?<=[a-z])-(?=[a-z])")
_WORDS = re.compile(r"[a-z']+")


def _fold_leet(token: str) -> str:
    if any(c.isalpha() for c in token) and any(c in LEET_FOLD for c in token):
        return "".join(LEET_FOLD.get(c, c) for c in token)
    return token


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = "".join(HOMOGLYPH_FOLD.get(c, c) for c in text)
    text = _TOKEN.sub(lambda m: _fold_leet(m.group()), text)
    text = _INNER_HYPHEN.sub("", text.lower())
    return " ".join(text.split())


def _mostly_printable(data: bytes) -> str | None:
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s.strip():
        return None
    printable = sum(c.isprintable() or c.isspace() for c in s)
    return s if printable / len(s) >= 0.9 else None


def decode_candidates(text: str) -> list[str]:
    out = []
    for m in _B64.finditer(text):
        try:
            decoded = _mostly_printable(base64.b64decode(m.group(), validate=False))
        except (binascii.Error, ValueError):
            continue
        if decoded:
            out.append(decoded)
    for m in _HEX.finditer(text):
        try:
            decoded = _mostly_printable(bytes.fromhex(m.group()))
        except ValueError:
            continue
        if decoded:
            out.append(decoded)
    if text.strip():
        out.append(codecs.encode(text, "rot13"))
    return [c for c in out if c != text and _looks_like_text(c)]


def _looks_like_text(s: str) -> bool:
    letters = sum(c.isalpha() for c in s)
    return letters / max(len(s), 1) >= 0.5


def _bigrams(text: str) -> list[str]:
    words = _WORDS.findall(normalize(text))
    return [f"{a} {b}" for a, b in zip(words, words[1:], strict=False) if len(a) >= 3 and len(b) >= 3]


class Defender:
    def __init__(self, guard: PromptGuard | None = None):
        self.guard = guard or PromptGuard()
        self.level = 0
        self.learned: set[str] = set()

    def _scan(self, text: str) -> bool:
        return self.guard.scan(text).is_suspicious

    def blocks(self, text: str) -> bool:
        if not text.strip():
            return False
        if self._scan(text):
            return True
        if self.level < 1:
            return False
        norm = normalize(text)
        if self._scan(norm):
            return True
        if self.level >= 2:
            for cand in decode_candidates(text):
                if self._scan(cand) or self._scan(normalize(cand)):
                    return True
        if self.level >= 3 and self.learned:
            return any(b in self.learned for b in _bigrams(text))
        return False

    def harden(self, evaded: list[Sample], benign: list[Sample]) -> None:
        self.level = min(self.level + 1, MAX_LEVEL)
        if self.level >= MAX_LEVEL:
            self._learn(evaded, benign)

    def _learn(self, evaded: list[Sample], benign: list[Sample]) -> None:
        benign_bigrams = {b for s in benign for b in _bigrams(s.text)}
        counts = Counter(b for s in evaded for b in set(_bigrams(s.text)) if b not in benign_bigrams)
        cap = int(BENIGN_FP_CAP * len(benign))
        baseline = sum(self.blocks(s.text) for s in benign)
        for bigram, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:LEARN_PER_ROUND]:
            self.learned.add(bigram)
            if sum(self.blocks(s.text) for s in benign) > max(cap, baseline):
                self.learned.discard(bigram)
