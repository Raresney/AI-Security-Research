import logging
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from core.config import REPORTS_DIR
from core.llm_client import LLMClient
from core.utils import timestamp

from .corpus import load_attacks, load_benign
from .defender import Defender
from .engine import holdout_evasion, run_arena, split_samples
from .llm_mutator import LLMMutator
from .report import write_html, write_json

console = Console()


@click.group()
def main():
    """Red vs blue arena: mutate injection payloads against an adaptive prompt filter."""


@main.command()
@click.option("--rounds", default=6, show_default=True, help="Number of rounds")
@click.option("--seed", default=1, show_default=True, help="Seed for the rule-based mutators")
@click.option("--llm", is_flag=True, help="Also let a language model rewrite blocked payloads")
@click.option("--output", "-o", is_flag=True, help="Write JSON and HTML reports to reports/")
def run(rounds: int, seed: int, llm: bool, output: bool):
    """Run the arena and print one row per round."""
    logging.basicConfig(format="%(message)s")
    mutator = None
    if llm:
        try:
            mutator = LLMMutator(LLMClient(timeout=30.0, retries=0))
        except Exception as exc:
            reason = (str(exc).splitlines() or ["unknown error"])[0]
            console.print(f"No language model reachable ({reason}). Using rule-based mutators only.")

    train_attacks, held_out = split_samples(load_attacks(), 0.7, seed)
    benign_fit, benign_eval = split_samples(load_benign(), 0.6, seed)
    defender = Defender()
    records = run_arena(
        train_attacks, benign_fit, rounds=rounds, seed=seed, defender=defender,
        llm_mutator=mutator, benign_eval=benign_eval,
    )

    table = Table(title="Arena")
    for col in ("Round", "Defender", "Attacks", "Evaded", "Evasion", "FP rate"):
        table.add_column(col, justify="right")
    for r in records:
        table.add_row(
            str(r.round), f"level {r.defender_level}", str(r.attacks), str(r.evaded),
            f"{r.evasion_rate:.1%}", f"{r.fp_rate:.1%}",
        )
    console.print(table)

    evaded, total = holdout_evasion(defender, held_out, seed=seed + 98)
    rate = f"{evaded / total:.1%}" if total else "n/a"
    console.print(
        f"Held-out check: {evaded} of {total} fresh mutations of {len(held_out)} unseen attacks still evade "
        f"the level {defender.level} defender ({rate})."
    )
    console.print(
        f"False positives are measured on {len(benign_eval)} benign prompts the defender never trained on."
    )

    if output:
        stamp = timestamp()
        base = Path(REPORTS_DIR)
        meta = {
            "seed": seed,
            "llm": mutator is not None and mutator.available,
            "train_attacks": len(train_attacks),
            "held_out_attacks": len(held_out),
            "benign_eval": len(benign_eval),
            "holdout": {"evaded": evaded, "total": total},
        }
        write_json(records, base / f"arena_{stamp}.json", meta)
        write_html(records, base / f"arena_{stamp}.html", meta)
        console.print(f"Reports written to {base}/arena_{stamp}.(json|html)")


if __name__ == "__main__":
    main()
