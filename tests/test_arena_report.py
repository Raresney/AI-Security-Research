import json
import re

from click.testing import CliRunner

from arena.cli import main
from arena.engine import RoundRecord
from arena.report import mutator_table, write_html, write_json


def records():
    return [
        RoundRecord(1, 0, 61, 30, 0.4918, 1, 0.0098, {"seed": 30}),
        RoundRecord(2, 1, 61, 12, 0.1967, 1, 0.0098, {"homoglyph": 5, "leet": 7}),
        RoundRecord(3, 2, 61, 6, 0.0984, 1, 0.0098, {"leet": 2, "language_switch": 4}),
    ]


def test_json_roundtrip(tmp_path):
    path = tmp_path / "out.json"
    write_json(records(), path, meta={"seed": 4, "llm": False, "holdout": {"evaded": 2, "total": 100}})
    data = json.loads(path.read_text(encoding="utf-8"))
    assert [d["round"] for d in data["rounds"]] == [1, 2, 3]
    assert data["rounds"][1]["winning_mutators"] == {"homoglyph": 5, "leet": 7}
    assert data["meta"]["seed"] == 4 and data["meta"]["holdout"]["total"] == 100


def test_html_is_self_contained(tmp_path):
    path = tmp_path / "out.html"
    write_html(records(), path)
    html = path.read_text(encoding="utf-8")
    assert "http" not in html
    assert "<script src" not in html and "<link" not in html


def test_html_has_one_row_per_round(tmp_path):
    path = tmp_path / "out.html"
    write_html(records(), path)
    html = path.read_text(encoding="utf-8")
    assert len(re.findall(r'<tr class="round">', html)) == 3


def test_html_chart_has_both_series(tmp_path):
    path = tmp_path / "out.html"
    write_html(records(), path)
    html = path.read_text(encoding="utf-8")
    assert html.count("<polyline") == 2


def test_html_handles_empty_records(tmp_path):
    path = tmp_path / "out.html"
    write_html([], path)
    assert path.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_mutator_table_aggregates_by_level():
    table = mutator_table(records())
    assert table["leet"] == {1: 7, 2: 2}
    assert table["seed"] == {0: 30}


def test_cli_run_smoke():
    result = CliRunner().invoke(main, ["run", "--rounds", "2", "--seed", "1"])
    assert result.exit_code == 0, result.output
    assert "Round" in result.output
    assert "Held-out check" in result.output


def test_cli_output_writes_files(tmp_path, monkeypatch):
    monkeypatch.setattr("arena.cli.REPORTS_DIR", tmp_path)
    result = CliRunner().invoke(main, ["run", "--rounds", "2", "--seed", "1", "--output"])
    assert result.exit_code == 0, result.output
    assert list(tmp_path.glob("arena_*.json")) and list(tmp_path.glob("arena_*.html"))


def test_cli_llm_unreachable_still_completes(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("No LLM provider available")

    monkeypatch.setattr("arena.cli.LLMClient", boom)
    result = CliRunner().invoke(main, ["run", "--rounds", "2", "--seed", "1", "--llm"])
    assert result.exit_code == 0, result.output
    assert "rule-based" in result.output


def test_html_shows_meta_and_holdout(tmp_path):
    path = tmp_path / "out.html"
    write_html(records(), path, meta={"seed": 4, "llm": True, "holdout": {"evaded": 2, "total": 100}})
    html = path.read_text(encoding="utf-8")
    assert "seed 4" in html and "2 of 100" in html


def test_cli_unreachable_message_is_one_line(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("No LLM provider available. Either:\n  1. Start Ollama\n  2. Set GROQ_API_KEY")

    monkeypatch.setattr("arena.cli.LLMClient", boom)
    result = CliRunner().invoke(main, ["run", "--rounds", "1", "--seed", "1", "--llm"])
    assert "1. Start Ollama" not in result.output
    assert "rule-based" in result.output


def test_cli_holdout_line_names_unseen_attacks():
    result = CliRunner().invoke(main, ["run", "--rounds", "1", "--seed", "1"])
    assert "unseen attacks" in result.output
