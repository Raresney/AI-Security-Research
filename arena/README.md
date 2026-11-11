# Arena

A red vs blue loop between the attack payloads in this repo and `prompt_guard`.

Each round the attacker takes every payload that was blocked and mutates it. Payloads that got through are kept as they are. Then the defender hardens one level and the next round starts. The attacks and the benign prompts are each split up front. The defender only ever sees the training part. After the last round, a held-out check mutates the attacks it never saw, with a fresh seed, and counts how many still get through.

The defender is scored on two things at once: how many attacks it misses, and how many harmless prompts it wrongly flags. Without the second number a filter wins by blocking everything. The false positive rate is measured on benign prompts the defender never trained on.

## Usage

```bash
aisec-arena run                         # 6 rounds, seed 1
aisec-arena run --rounds 8 --output     # also writes reports/arena_<time>.json and .html
aisec-arena run --llm                   # let a local or hosted model rewrite blocked payloads too
```

The same seed gives the same result as long as `--llm` is off.

## What gets attacked

The seed pool has 61 payloads: the 26 cases from the injection lab (for multi-turn cases, the last user message), the 10 RAG poisoning documents, and the 25 malicious entries in `prompt_guard/known_injections`. The split is 70/30 by seed: 43 payloads are mutated during the rounds, 18 are kept back for the held-out check.

There are 102 benign prompts: the 25 in that corpus plus 77 in `arena/data/benign.json`, some of which mention words like "instructions" or "previous" on purpose. 61 are shown to the defender, 41 are used only to count false positives.

## Mutators

| Name | What it does |
|---|---|
| `homoglyph` | Swaps Latin letters for Cyrillic lookalikes |
| `zero_width` | Inserts zero-width spaces inside words |
| `leet` | Replaces letters with digits |
| `word_split` | Puts a hyphen inside long words |
| `base64_wrap`, `hex_wrap`, `rot13_wrap` | Encodes the payload and asks the model to decode and follow it |
| `language_switch` | Translates key phrases to Spanish, French, German or Romanian |

If a mutator would leave the text unchanged, another one is tried. With `--llm`, up to 10 blocked payloads per round are also rewritten by a model, and replies that are refusals are thrown away. If no model can be reached, the run prints one line and continues without it.

## Defender levels

| Level | Adds |
|---|---|
| 0 | `prompt_guard` as it ships |
| 1 | Normalization: strips invisible characters, folds homoglyphs and leetspeak, joins hyphenated words |
| 2 | Decodes base64, hex and rot13 and scans the result |
| 3 | Learns word pairs from payloads that evaded and flags them, in the raw text and in decoded text. Pairs made of common words, very long tokens, or anything seen in the benign training prompts are skipped. |

## Result

Default run, 6 rounds, seed 1:

| Round | Defender | Evaded | False positives |
|---|---|---|---|
| 1 | level 0 | 48.8% | 0.0% |
| 2 | level 1 | 65.1% | 0.0% |
| 3 | level 2 | 41.9% | 0.0% |
| 4 | level 3 | 41.9% | 0.0% |
| 5 | level 3 | 4.7% | 0.0% |
| 6 | level 3 | 7.0% | 0.0% |

![Arena report](../docs/screenshots/arena_report.png)

About half of the payloads already get past the stock filter in round 1. Each new defender level is followed by a jump in evasion, because the attacker's mutations are new to it. The curve falls in rounds 5 and 6 partly because the defender has now seen those exact payloads, so the rounds table flatters it.

The held-out check is the fairer number. It mutates 18 attacks the defender never saw, with 8 mutators each (144 variants). Over seeds 1 to 3:

| Defender | Fresh mutations that evade |
|---|---|
| level 0, stock filter | 93.5% (404 of 432) |
| level 2, normalization and decoding | 38.4% (166 of 432) |
| level 3, after 6 rounds | 28.0% (121 of 432) |

Normalization and decoding do most of the work. Learning word pairs from evaded payloads adds about 10 points on top. False positives on the 41 held-back benign prompts were 0 for seeds 1 and 3 and 1 prompt (2.4%) for seed 2.

Limits: the benign set is small, so one prompt moves the rate by 2.4 points. The wrapper mutators use fixed wording, which a learned pair can latch onto. `language_switch` only knows a handful of phrases. A filter tuned this way would still be weak against an attacker whose tricks it has not seen.
