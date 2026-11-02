# verdict_fuzz — mutate a corpus program, require the same verdict

The corpus is the spec (Q1 addition 2), but a green `corpus_harness.py` run
only proves the checker agrees with fixtures the same people wrote. It says
nothing about the spec's **edges**. This tool mutates a fixture in a way that
keeps it parseable and a reasonable reader would classify the same way, and
requires the registered verdict not to move.

`hyfuzz.py` mutates corpus programs too, but its invariants are only *no hang*,
*no crash*, *no ICE*. It never asks whether the mutated program still gets the
right verdict. This tool asks exactly that, and only that.

```
python3 tools/fuzz/verdict_fuzz.py --bin <path/to/hyb> [--per-file N] [--seed S]
```

Exit 1 on any flip (with `--failures-dir` the minimised program is written
out), 0 when every tried mutation held.

## The oracle

The parent fixture's `EXPECTED-VERDICT` header, read with the same parser
`corpus_harness.py` uses (`read_expected`), so a mutation is judged by the
registered contract rather than a second copy of it. The **rule id is not part
of the comparison**: a mutation may legitimately reach a neighbouring rule
while the verdict stays `reject`, and holding the rule id would report that as
a flip and bury the real finding under noise. `ACCEPT-MANAGED` normalises to
`accept`.

A mutation that does not parse is **skipped, not counted**. A parse failure
means the mutation left the language; testing the checker there measures the
parser.

## The hard part: a mutation that cannot change meaning

Four operators were written first; three were discarded after measurement.
Each discarded one produced "flips" that were really *different programs*, and
reporting those would have been worse than reporting nothing. The reasons are
kept here because the next person will reach for the same operators.

| Operator | Why it was removed |
|---|---|
| `identity-rename` | A single-scope rename must avoid members (`fmt.println`), dotted roots (`g.nodes`), builtins dispatched by name (`min`, `max`, `len`), import paths, `package` operands, parameter names, type names (`any`), `default:` arms and the `main` entry point. Missing any one yields a different, usually invalid, program. On 780 mutations it reported 20–59 "flips", all artefacts. |
| `duplicate-stmt` | Idempotence is not decidable syntactically: a duplicated struct field, `managed` header or `default:` arm is a different and invalid program. |
| `number` (naive) | `var hi int8 = 127` → 254 is genuinely invalid, so `REJECT` is correct. Also `[N]` array lengths an index relies on, and `int(3.0)` → `int(3.1)`, which is a real error. Bounded now. |
| `paren` (naive) | Appending `)` at end-of-line puts it inside a trailing `//` comment and truncates the statement — a syntax error, not a regrouping. Fixed. |

What ships changes a value within range, a grouping, or adds a
declared-and-discarded local. None can change which rules a program is expected
to satisfy.

## Measured result

```
130 corpus fixtures, 397 mutations, 7 seeds  ->  0 verdict flips
```

## Why a 0 matters only if the detector can fire

A "0 flips" result from a tool that can never fire is indistinguishable from a
perfect score, so the negative control is part of the test suite. Neuter a real
check — `fn finish()` in `buildable.rs` early-returning, which drops the
unused-binding rule — and the same run reports:

```
FLIP  46-unused-define-reject.hy   comment-blank   expected=reject   got=accept
FLIP  46-unused-define-reject.hy   paren           expected=reject   got=accept
mutations tried   : 397
verdict flips     : 3
```

Restore the check and the count returns to 0. `tools/test_verdict_fuzz.py`
pins both directions (`DetectionTests`).

## What this does not prove

Zero flips over 397 mutations means **the corpus is not obviously under-pinned
by these four operators**. It is not a proof of corpus completeness, and it is
not a soundness claim about the checker: a mutation my operators cannot express
is a rule this tool cannot see. The honest reading is that the detections
available to these four operators are currently all held.

`comment-blank` is the tool's own control — editing a comment must never change
a verdict. If it ever does, the failure is in the harness, not the checker.
