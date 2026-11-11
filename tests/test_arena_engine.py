import pytest

from arena import engine
from arena.corpus import Sample
from arena.engine import run_arena


class FakeDefender:
    """Blocks everything unless the text contains EVADE."""

    def __init__(self):
        self.level = 0
        self.hardened = 0

    def blocks(self, text):
        return "EVADE" not in text

    def matched(self, text):
        return ["override"]

    def harden(self, evaded, benign):
        self.hardened += 1
        self.level += 1


class FakeLLM:
    def __init__(self, reply="auto"):
        self.reply = reply
        self.calls = []

    def rewrite(self, text, matched):
        self.calls.append(text)
        return f"{text} rewritten EVADE" if self.reply == "auto" else self.reply


def attacks(*texts):
    return [Sample(f"a{i}", "t", t, "attack") for i, t in enumerate(texts)]


def benign(*texts):
    return [Sample(f"b{i}", "t", t, "benign") for i, t in enumerate(texts)]


@pytest.fixture
def fake_mutate(monkeypatch):
    monkeypatch.setattr(engine, "mutate", lambda text, rng, name=None: (text + " EVADE", "fake"))


def test_round_count_equals_rounds(fake_mutate):
    assert len(run_arena(attacks("x"), benign("ok"), rounds=4, seed=1, defender=FakeDefender())) == 4


def test_blocked_samples_get_mutated_each_round(fake_mutate):
    recs = run_arena(attacks("x"), benign("ok"), rounds=3, seed=1, defender=FakeDefender())
    assert [r.evaded for r in recs] == [0, 1, 1]


def test_evaded_samples_carry_over(fake_mutate):
    recs = run_arena(attacks("a EVADE"), benign("ok"), rounds=3, seed=1, defender=FakeDefender())
    assert [r.attacks for r in recs] == [1, 1, 1]
    assert [r.evaded for r in recs] == [1, 1, 1]
    assert recs[0].winning_mutators == {"seed": 1}


def test_winning_mutators_name_the_mutator(fake_mutate):
    recs = run_arena(attacks("x"), benign("ok"), rounds=2, seed=1, defender=FakeDefender())
    assert recs[1].winning_mutators == {"fake": 1}


def test_harden_called_once_per_round(fake_mutate):
    d = FakeDefender()
    run_arena(attacks("x"), benign("ok"), rounds=5, seed=1, defender=d)
    assert d.hardened == 5


def test_defender_level_recorded_at_scan_time(fake_mutate):
    recs = run_arena(attacks("x"), benign("ok"), rounds=3, seed=1, defender=FakeDefender())
    assert [r.defender_level for r in recs] == [0, 1, 2]


def test_fp_rate_from_benign(fake_mutate):
    recs = run_arena(attacks("x"), benign("a", "b EVADE"), rounds=1, seed=1, defender=FakeDefender())
    assert recs[0].benign_flagged == 1
    assert recs[0].fp_rate == 0.5


def test_empty_attack_list(fake_mutate):
    recs = run_arena([], benign("a"), rounds=2, seed=1, defender=FakeDefender())
    assert [(r.attacks, r.evasion_rate) for r in recs] == [(0, 0.0), (0, 0.0)]


def test_empty_benign_list_has_zero_fp(fake_mutate):
    recs = run_arena(attacks("x"), [], rounds=1, seed=1, defender=FakeDefender())
    assert recs[0].fp_rate == 0.0


def test_same_seed_same_output():
    from arena.corpus import load_attacks, load_benign

    a, b = load_attacks()[:15], load_benign()[:15]
    one = run_arena(a, b, rounds=3, seed=5)
    two = run_arena(a, b, rounds=3, seed=5)
    assert one == two


def test_llm_rewrites_only_blocked_and_respect_limit(fake_mutate):
    llm = FakeLLM()
    recs = run_arena(
        attacks("a", "b", "c", "d EVADE"), benign("ok"), rounds=2, seed=1,
        defender=FakeDefender(), llm_mutator=llm, llm_limit=2,
    )
    assert len(llm.calls) == 2
    assert "d EVADE" not in llm.calls
    assert recs[1].winning_mutators.get("llm") == 2


def test_llm_none_reply_is_skipped(fake_mutate):
    recs = run_arena(
        attacks("a"), benign("ok"), rounds=2, seed=1,
        defender=FakeDefender(), llm_mutator=FakeLLM(reply=None),
    )
    assert "llm" not in recs[1].winning_mutators


def test_very_long_text_is_not_mutated(fake_mutate):
    long = "x" * 5000
    recs = run_arena(attacks(long), benign("ok"), rounds=2, seed=1, defender=FakeDefender())
    assert recs[1].evaded == 0


def test_duplicate_texts_collapse(fake_mutate):
    recs = run_arena(attacks("a EVADE", "a EVADE"), benign("ok"), rounds=1, seed=1, defender=FakeDefender())
    assert recs[0].attacks == 1


def test_holdout_applies_every_mutator_to_every_seed():
    from arena.mutators import MUTATORS

    evaded, total = engine.holdout_evasion(FakeDefender(), attacks("a", "b"), seed=3)
    assert total == 2 * len(MUTATORS)
    assert evaded == 0


def test_holdout_counts_evasions(monkeypatch):
    monkeypatch.setattr(engine, "MUTATORS", {"one": lambda t, rng: t + " EVADE", "two": lambda t, rng: t})
    assert engine.holdout_evasion(FakeDefender(), attacks("a"), seed=1) == (1, 2)


def test_holdout_is_deterministic_per_seed():
    from arena.corpus import load_attacks

    a = load_attacks()[:10]
    assert engine.holdout_evasion(engine.Defender(), a, seed=4) == engine.holdout_evasion(engine.Defender(), a, seed=4)


def test_split_is_deterministic_disjoint_and_complete():
    items = attacks(*[f"t{i}" for i in range(20)])
    a1, b1 = engine.split_samples(items, 0.7, seed=3)
    a2, b2 = engine.split_samples(items, 0.7, seed=3)
    assert (a1, b1) == (a2, b2)
    assert len(a1) == 14 and len(b1) == 6
    assert not set(a1) & set(b1)
    assert set(a1) | set(b1) == set(items)


def test_split_differs_by_seed():
    items = attacks(*[f"t{i}" for i in range(20)])
    assert engine.split_samples(items, 0.7, seed=1) != engine.split_samples(items, 0.7, seed=2)


def test_fp_rate_uses_benign_eval_when_given(fake_mutate):
    recs = run_arena(
        attacks("x"), benign("a EVADE"), rounds=1, seed=1, defender=FakeDefender(),
        benign_eval=benign("p", "q", "r EVADE", "s EVADE"),
    )
    assert recs[0].benign_flagged == 2
    assert recs[0].fp_rate == 0.5
