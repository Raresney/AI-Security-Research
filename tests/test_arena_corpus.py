from arena.corpus import Sample, load_attacks, load_benign


def test_attack_count_is_61():
    assert len(load_attacks()) == 61


def test_benign_at_least_100():
    assert len(load_benign()) >= 100


def test_ids_unique_across_both_sets():
    ids = [s.id for s in load_attacks() + load_benign()]
    assert len(ids) == len(set(ids))


def test_labels_match_sets():
    assert {s.label for s in load_attacks()} == {"attack"}
    assert {s.label for s in load_benign()} == {"benign"}


def test_sources_cover_all_three_attack_origins():
    assert {s.source for s in load_attacks()} == {"injection_lab", "rag_poison", "guard_corpus"}


def test_no_empty_text():
    assert all(s.text.strip() for s in load_attacks() + load_benign())


def test_no_benign_contains_classic_attack_phrase():
    assert not [s for s in load_benign() if "ignore all previous instructions" in s.text.lower()]


def test_sample_is_hashable():
    assert len({Sample("a", "x", "t", "attack"), Sample("a", "x", "t", "attack")}) == 1
