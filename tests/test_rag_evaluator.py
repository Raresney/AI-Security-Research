import pytest

pytest.importorskip("chromadb", exc_type=ImportError)

from rag_poison_lab.evaluator import RAGEvaluator  # noqa: E402


def make():
    return RAGEvaluator(store=None, llm=None)


def test_indicator_match_is_case_insensitive():
    hits = make()._check_poison_success("The login is ADMIN / company2025!", ["admin", "Company2025"])
    assert hits == ["admin", "Company2025"]


def test_clean_answer_has_no_hits():
    assert make()._check_poison_success("Use the self-service reset portal.", ["admin", "Company2025"]) == []


def test_retrieved_poisoned_flag():
    ev = make()
    assert ev._retrieved_poisoned_doc([{"metadata": {"poisoned": "true"}}])
    assert not ev._retrieved_poisoned_doc([{"metadata": {}}])
