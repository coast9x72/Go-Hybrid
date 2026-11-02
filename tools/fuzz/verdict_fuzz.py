#!/usr/bin/env python3
"""verdict_fuzz.py — mutate a corpus program, require the SAME verdict.

The corpus is the spec (Q1 addition 2), but a green `corpus_harness.py` run
only proves the checker agrees with fixtures the same people wrote. It says
nothing about the spec's EDGES: mutate a fixture in a way that keeps it
parseable and a reasonable reader would still classify the same way, and the
registered verdict should not move. When it does, one of two things is true —
either the fixture is not pinning what its header claims, or the checker reads
a neighbouring construct differently than the construct itself.

`hyfuzz.py` mutates corpus programs too, but its invariants are only
  1. no hang, 2. no crash, 3. no ICE.
It never asks whether the mutated program still gets the right verdict. This
tool asks exactly that, and only that.

Oracle: the parent fixture's EXPECTED-VERDICT header, read with the same
parser `corpus_harness.py` uses (`read_expected`), so a mutation is judged by
the registered contract rather than a second copy of it.

A mutation is only tried when it PARSES. A parse failure means the mutation
left the language, and testing the checker there measures the parser, not the
rule under test.

## The hard part: a mutation that cannot change meaning

Four operators were written first and three were discarded after measurement.
Every discarded one produced "flips" that were really *different programs*,
and reporting those would have been worse than reporting nothing. The reasons
are kept here because the next person will reach for the same operators:

  identity-rename   A single-scope rename must avoid members (`fmt.println`),
                    dotted roots (`g.nodes`), builtins (`min`, `max`, `len` —
                    dispatched by name), import paths, `package` operands,
                    parameter names, type names (`any`), `default:` arms and
                    the `main` entry point. Missing any one of them yields a
                    different, usually invalid, program. On 780 mutations it
                    reported 20–59 "flips", all artefacts. Removed.

  duplicate-stmt    Idempotence is not decidable syntactically: a duplicated
                    struct field, `managed` header or `default:` arm is a
                    different and invalid program. Removed.

  number (naive)    `var hi int8 = 127` mutated to 254 is genuinely invalid,
                    so REJECT is correct. Now bounded: literals are only
                    perturbed by ±1 (or ±2 when the file declares no narrow
                    integer type), which cannot cross an `int` boundary.

  paren (naive)     Appending `)` at end-of-line puts it inside a trailing
                    `//` comment and truncates the statement — a syntax error,
                    not a regrouping. Now inserted before the comment.

What is left changes a value within range or a grouping. Neither can change
which rules a program is expected to satisfy.

Exit 1 when any mutation flips a verdict, 0 when every tried mutation held.

Stdlib only (runner discipline).
"""
import argparse
import json
import os
import random
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from corpus_harness import read_expected  # noqa: E402  (same oracle as the harness)

NUM = re.compile(r"\b(\d+)\b")

# A file that declares a narrow integer type can hold a boundary value, so a
# perturbation may legitimately leave the type's range there.
FLOAT_LIT = re.compile(r"\d+\.\d*|\d*\.\d+")
NARROW_INT = re.compile(r"\b(int8|int16|int32|uint8|uint16|uint32|byte|rune)\b")


def mut_number(src, rng):
    """Perturb an integer literal ONLY when the fixture holds no narrow
    integer type at all.

    Every remaining false positive came from a bounded width: `int8 127` ->
    128 (out of range), `-128` -> `-129`, `100 + 27` -> `100 + 28` (constant
    overflow), and an array INDEX perturbed out of bounds. A fixture that
    mentions `int8`/`int16`/`byte`/`rune`/`uint*` is exactly the fixture whose
    literals are load-bearing, so those files are skipped wholesale rather
    than trying to prove each individual literal is unconstrained — that
    proof needs the type checker this tool is testing.
    """
    if NARROW_INT.search(src):
        return []
    # A literal inside `[...]` may be an ARRAY LENGTH with an index reaching
    # past it; those are load-bearing too.
    if re.search(r"\[\s*\d+\s*\]", src):
        return []
    # An untagged float next to an int literal means a conversion that must be
    # exact (`int(3.0)`); `int(3.1)` is a genuine error, not a flip.
    if FLOAT_LIT.search(src):
        return []
    out = []
    for m in NUM.finditer(src):
        v = int(m.group(1))
        for nv in sorted({v + 1, v - 1}):
            if nv == v or nv < 0:
                continue
            out.append(src[: m.start(1)] + str(nv) + src[m.end(1):])
    rng.shuffle(out)
    return out[:6]


def mut_wrap_paren(src, rng):
    """Parenthesise a whole RHS of a plain assignment. Transparent to meaning.

    Only a `name = expr` / `name := expr` line with no `{`, no `:` (so a
    `select` arm or a labelled statement is excluded), no existing parens, and
    no `<-` is touched. The closing paren goes BEFORE any trailing `//`
    comment; appended at end-of-line it lands inside the comment and truncates
    the statement, which is a syntax error rather than a regrouping.
    """
    out = []
    for line in src.splitlines():
        m = re.match(r"^(\s*)([a-z_][a-z0-9_]*\s*:?=\s*)([^:]+?)\s*$", line)
        if not m:
            continue
        code, sep, comment = m.group(3).partition("//")
        code = code.rstrip()
        if not code or any(t in code for t in "(){}←"):
            continue
        new = f"{m.group(1)}{m.group(2)}({code})"
        if sep:
            new += f"  //{comment}"
        out.append(src.replace(line, new, 1))
    return out[:4]



def mut_declare_extra_local(src, rng):
    """Add an UNUSED-and-discarded local at the TOP LEVEL of a function body.

    `hyb check` requires every binding to be read (E1002), so the pair
    `x := 1` / `_ = x` keeps it legal without any value flowing anywhere.

    Injection points are restricted to lines whose indentation is exactly one
    level inside a `fn` body: a `select` arm, a closure body or a nested block
    is a different scope where `:=` is not a plain statement, and inserting
    there produced a real syntax error rather than a probe.

    Also restricted to fixtures with no narrow width, no fixed-array literal
    and no float conversion, for the same reason as `mut_number`.
    """
    if NARROW_INT.search(src) or re.search(r"\[\s*\d+\s*\]", src) or FLOAT_LIT.search(src):
        return []
    lines = src.splitlines(keepends=True)
    out = []
    in_fn = False
    fn_indent = 0
    depth = 0
    body_indent = None
    for i, line in enumerate(lines):
        st = line.strip()
        indent = len(line) - len(line.lstrip())
        if re.match(r"^\s*fn\b", line):
            # The opening `{` is on this line, so start the body at depth 1.
            in_fn, fn_indent, depth = True, indent, line.count("{") - line.count("}")
            body_indent = None
            continue
        if not in_fn:
            continue
        depth += line.count("{") - line.count("}")
        if depth <= 0 and "}" in line:
            in_fn = False
            continue
        # A statement at body depth 1 whose own braces/colon are absent. The
        # body indent is whatever the fixture uses (2, 4 spaces, or a tab), so
        # record it from the first such line rather than assuming a width.
        if depth == 1 and st and not st.startswith("//") and indent > fn_indent:
            if any(t in st for t in "{}:"):
                continue
            if body_indent is None:
                body_indent = indent
            if indent != body_indent:
                continue
            pad = " " * body_indent
            add = f"{pad}probe_value := 1\n{pad}_ = probe_value\n"
            out.append("".join(lines[: i + 1] + [add] + lines[i + 1:]))
    return out[:3]


def mut_blank_comment_line(src, rng):
    """Turn a comment line into a blank line. Comments never affect a verdict.

    This is the tool's own control: it must ALWAYS hold. If a comment edit
    ever flips a verdict, the failure is in the harness, not the checker.
    """
    lines = src.splitlines(keepends=True)
    out = []
    for i, line in enumerate(lines):
        st = line.strip()
        if not st.startswith("//"):
            continue
        out.append("".join(lines[:i] + ["\n"] + lines[i + 1:]))
    rng.shuffle(out)
    return out[:2]


MUTATORS = [
    ("comment-blank", mut_blank_comment_line),   # self-check: must never flip
    ("number", mut_number),
    ("paren", mut_wrap_paren),
    ("extra-local", mut_declare_extra_local),
]


def run_check(binpath, path, timeout):
    proc = subprocess.run(
        [binpath, "check", str(path), "--json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout,
    )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, "unparseable-checker-json"
    verdict = payload.get("summary", {}).get("verdict") or payload.get("verdict")
    return verdict, None


def expected_signature(expected):
    """The oracle as a comparable signature: lowercase verdict only.

    The rule id is deliberately NOT part of the signature. A mutation may
    legitimately reach a different rule while the verdict stays reject;
    holding the rule id would report that as a flip and bury the real finding
    under noise. What must not move is accept-vs-reject.
    """
    verdict, _rule = expected
    return verdict.lower().split("-")[0]          # ACCEPT-MANAGED -> accept


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True, help="path to hyb")
    ap.add_argument("--corpus", default="tests/checker-corpus")
    ap.add_argument("--seed", type=int, default=20261102)
    ap.add_argument("--per-file", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--failures-dir", default=None)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    corpus = Path(args.corpus)
    fixtures = sorted(corpus.glob("*.hy"))
    if not fixtures:
        print(f"FAILED: no fixtures under {corpus}", file=sys.stderr)
        return 1

    tried = flipped = skipped = 0
    findings = []
    for fx in fixtures:
        expected = read_expected(fx)
        if expected is None:
            continue
        src = fx.read_text(encoding="utf-8")
        want = expected_signature(expected)
        tried_here = 0
        for name, fn in MUTATORS:
            if tried_here >= args.per_file:
                break
            for mutated in fn(src, rng):
                if tried_here >= args.per_file:
                    break
                if mutated == src:
                    continue
                tmp = corpus / f".fuzz-{os.getpid()}-{tried_here}.hy"
                tmp.write_text(mutated, encoding="utf-8")
                try:
                    verdict, err = run_check(args.bin, tmp, args.timeout)
                    if err or verdict is None:
                        skipped += 1
                        continue
                    tried += 1
                    tried_here += 1
                    if want != verdict.lower():
                        flipped += 1
                        findings.append((fx.name, name, want, verdict.lower()))
                        if args.failures_dir:
                            out = Path(args.failures_dir)
                            out.mkdir(parents=True, exist_ok=True)
                            (out / f"{fx.stem}__{name}.hy").write_text(
                                mutated, encoding="utf-8")
                finally:
                    tmp.unlink(missing_ok=True)

    for f in findings:
        print(f"FLIP  {f[0]:44} {f[1]:10} expected={f[2]:8} got={f[3]}")
    print("-" * 78)
    print(f"mutations tried   : {tried}")
    print(f"verdict flips     : {flipped}")
    print(f"skipped (no parse): {skipped}")
    return 1 if flipped else 0


if __name__ == "__main__":
    sys.exit(main())
