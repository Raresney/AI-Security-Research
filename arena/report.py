import json
from collections import defaultdict
from html import escape
from pathlib import Path

from .engine import RoundRecord

W, H = 640, 280
ML, MR, MT, MB = 52, 16, 16, 40

STYLE = """
:root { --bg:#fbfaf8; --fg:#1d1d1b; --muted:#6b6a66; --line:#dcd9d2; --evade:#c2410c; --fp:#1d6fa5; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#17171a; --fg:#e8e6e1; --muted:#9a978f; --line:#34343a; --evade:#f08a5d; --fp:#6cb4e4; }
}
body { background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, sans-serif; margin:0; padding:32px 16px; }
main { max-width:760px; margin:0 auto; }
h1 { font-size:22px; margin:0 0 4px; }
h2 { font-size:16px; margin:32px 0 8px; }
p.note { color:var(--muted); margin:0 0 16px; }
table { border-collapse:collapse; width:100%; font-variant-numeric:tabular-nums; }
th, td { text-align:right; padding:6px 10px; border-bottom:1px solid var(--line); }
th:first-child, td:first-child { text-align:left; }
svg { width:100%; height:auto; display:block; }
svg text { fill:var(--muted); font-size:11px; }
.legend { display:flex; gap:20px; color:var(--muted); font-size:13px; margin-top:6px; }
.legend i { display:inline-block; width:12px; height:3px; margin-right:6px; vertical-align:middle; }
"""


def write_json(records: list[RoundRecord], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([r.to_dict() for r in records], indent=2), encoding="utf-8")


def mutator_table(records: list[RoundRecord]) -> dict[str, dict[int, int]]:
    table: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for r in records:
        for name, count in r.winning_mutators.items():
            table[name][r.defender_level] += count
    return {name: dict(levels) for name, levels in sorted(table.items())}


def _x(i: int, n: int) -> float:
    inner = W - ML - MR
    return ML + (inner / 2 if n == 1 else inner * i / (n - 1))


def _y(value: float) -> float:
    return MT + (H - MT - MB) * (1 - value)


def _series(values: list[float], css_var: str) -> str:
    n = len(values)
    pts = " ".join(f"{_x(i, n):.1f},{_y(v):.1f}" for i, v in enumerate(values))
    dots = "".join(
        f'<circle cx="{_x(i, n):.1f}" cy="{_y(v):.1f}" r="3" fill="var({css_var})"/>'
        for i, v in enumerate(values)
    )
    return f'<polyline points="{pts}" fill="none" stroke="var({css_var})" stroke-width="2"/>{dots}'


def _chart(records: list[RoundRecord]) -> str:
    parts = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Evasion and false positive rate per round">']
    for pct in (0, 25, 50, 75, 100):
        y = _y(pct / 100)
        parts.append(f'<line x1="{ML}" x2="{W - MR}" y1="{y:.1f}" y2="{y:.1f}" stroke="var(--line)"/>')
        parts.append(f'<text x="{ML - 8}" y="{y + 4:.1f}" text-anchor="end">{pct}%</text>')
    n = len(records)
    for i, r in enumerate(records):
        parts.append(f'<text x="{_x(i, n):.1f}" y="{H - 14}" text-anchor="middle">{r.round}</text>')
    parts.append(f'<text x="{(ML + W - MR) / 2:.1f}" y="{H - 1}" text-anchor="middle">round</text>')
    if records:
        parts.append(_series([r.evasion_rate for r in records], "--evade"))
        parts.append(_series([r.fp_rate for r in records], "--fp"))
    parts.append("</svg>")
    return "".join(parts)


def _round_rows(records: list[RoundRecord]) -> str:
    return "".join(
        f'<tr class="round"><td>{r.round}</td><td>{r.defender_level}</td><td>{r.attacks}</td>'
        f"<td>{r.evaded}</td><td>{r.evasion_rate:.1%}</td><td>{r.benign_flagged}</td><td>{r.fp_rate:.1%}</td></tr>"
        for r in records
    )


def _mutator_rows(records: list[RoundRecord]) -> tuple[str, str]:
    table = mutator_table(records)
    levels = sorted({lvl for row in table.values() for lvl in row})
    head = "<tr><th>mutator</th>" + "".join(f"<th>level {lvl}</th>" for lvl in levels) + "</tr>"
    body = "".join(
        f"<tr><td>{escape(name)}</td>" + "".join(f"<td>{row.get(lvl, 0)}</td>" for lvl in levels) + "</tr>"
        for name, row in table.items()
    )
    return head, body


def write_html(records: list[RoundRecord], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    head, body = _mutator_rows(records)
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arena report</title>
<style>{STYLE}</style>
</head>
<body>
<main>
<h1>Red vs blue arena</h1>
<p class="note">Attack payloads are mutated each round while the prompt filter hardens. The orange line is the share of attacks
that got through, the blue line is the share of benign prompts the filter wrongly flagged.</p>
{_chart(records)}
<div class="legend"><span><i style="background:var(--evade)"></i>attacks that evaded</span><span><i style="background:var(--fp)"></i>benign flagged</span></div>
<h2>Rounds</h2>
<table>
<tr><th>round</th><th>defender level</th><th>attacks</th><th>evaded</th><th>evasion</th><th>benign flagged</th><th>false positive</th></tr>
{_round_rows(records)}
</table>
<h2>Which mutators got through, by defender level</h2>
<table>
{head}
{body}
</table>
</main>
</body>
</html>
"""
    path.write_text(page, encoding="utf-8")
