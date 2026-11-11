import random
from collections import Counter
from dataclasses import asdict, dataclass

from .corpus import Sample
from .defender import Defender
from .mutators import MUTATORS, mutate

MAX_MUTATE_LEN = 4000


@dataclass
class RoundRecord:
    round: int
    defender_level: int
    attacks: int
    evaded: int
    evasion_rate: float
    benign_flagged: int
    fp_rate: float
    winning_mutators: dict[str, int]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Attack:
    text: str
    mutator: str


def _dedupe(pool: list[Attack]) -> list[Attack]:
    seen, out = set(), []
    for a in pool:
        if a.text not in seen:
            seen.add(a.text)
            out.append(a)
    return out


def run_arena(
    attacks: list[Sample],
    benign: list[Sample],
    rounds: int,
    seed: int,
    defender: Defender | None = None,
    llm_mutator=None,
    llm_limit: int = 10,
) -> list[RoundRecord]:
    defender = defender or Defender()
    rng = random.Random(seed)
    pool = _dedupe([Attack(s.text, "seed") for s in attacks])
    records = []

    for n in range(1, rounds + 1):
        verdicts = [(a, defender.blocks(a.text)) for a in pool]
        evaded = [a for a, was_blocked in verdicts if not was_blocked]
        blocked = [a for a, was_blocked in verdicts if was_blocked]
        flagged = sum(defender.blocks(b.text) for b in benign)
        records.append(
            RoundRecord(
                round=n,
                defender_level=defender.level,
                attacks=len(pool),
                evaded=len(evaded),
                evasion_rate=round(len(evaded) / len(pool), 4) if pool else 0.0,
                benign_flagged=flagged,
                fp_rate=round(flagged / len(benign), 4) if benign else 0.0,
                winning_mutators=dict(sorted(Counter(a.mutator for a in evaded).items())),
            )
        )

        next_pool = list(evaded)
        for a in blocked:
            if len(a.text) > MAX_MUTATE_LEN:
                next_pool.append(a)
                continue
            text, name = mutate(a.text, rng)
            next_pool.append(Attack(text, name))
        if llm_mutator is not None:
            for a in blocked[:llm_limit]:
                rewrite = llm_mutator.rewrite(a.text, defender.matched(a.text))
                if rewrite and len(rewrite) <= MAX_MUTATE_LEN:
                    next_pool.append(Attack(rewrite, "llm"))
        pool = _dedupe(next_pool)

        evaded_samples = [Sample(f"r{n}_{i}", "arena", a.text, "attack") for i, a in enumerate(evaded)]
        defender.harden(evaded_samples, benign)

    return records


def holdout_evasion(defender: Defender, attacks: list[Sample], seed: int = 99) -> tuple[int, int]:
    """Apply every mutator once to every original attack with a fresh seed and count what gets through."""
    rng = random.Random(seed)
    evaded = total = 0
    for a in attacks:
        for fn in MUTATORS.values():
            total += 1
            evaded += not defender.blocks(fn(a.text, rng))
    return evaded, total
