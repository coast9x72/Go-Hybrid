"""Tests for tools/fuzz/verdict_fuzz.py.

The tool's whole value rests on one claim: a flip it reports is the checker's,
not the mutator's. So the tests are mostly about the MUTATORS being safe, and
about the tool actually detecting a weakened checker — a "0 flips" result from
a detector that can never fire is indistinguishable from a perfect score.
"""
import contextlib
import importlib.util
import io
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "verdict_fuzz", Path(__file__).with_name("fuzz") / "verdict_fuzz.py"
)
vf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vf)


class MutatorSafetyTests(unittest.TestCase):
    """A mutator that can change meaning makes the tool report its own bugs."""

    def test_number_skips_narrow_width_fixtures(self):
        # `int8 127` -> 128 is genuinely out of range; REJECT would be correct.
        src = "fn main() {\n    var hi int8 = 127\n}\n"
        self.assertEqual(vf.mut_number(src, random.Random(1)), [])

    def test_number_skips_fixed_array_lengths(self):
        # A literal inside `[N]` may be a length an index relies on.
        src = "fn main() {\n    xs := [2]int{}\n}\n"
        self.assertEqual(vf.mut_number(src, random.Random(1)), [])

    def test_number_skips_float_conversion_fixtures(self):
        # `int(3.0)` must be exact; `int(3.1)` is a real error.
        src = "fn main() {\n    i := int(3.0)\n}\n"
        self.assertEqual(vf.mut_number(src, random.Random(1)), [])

    def test_paren_keeps_the_closing_paren_out_of_the_comment(self):
        src = "fn main() {\n    x := 1 + 2  // keep me\n}\n"
        out = vf.mut_wrap_paren(src, random.Random(1))
        self.assertTrue(out, "expected at least one mutation")
        mutated = out[0]
        self.assertIn("(1 + 2)", mutated, mutated)
        # The paren must precede the comment, or the statement is truncated.
        self.assertLess(mutated.index(")"), mutated.index("//"))

    def test_extra_local_lands_at_function_body_top_level(self):
        src = "fn main() {\n    select {\n        a <- b: {}\n    }\n}\n"
        # A select arm is a different scope; injecting there is a syntax error.
        self.assertEqual(vf.mut_declare_extra_local(src, random.Random(1)), [])

    def test_extra_local_pairs_declaration_with_a_use(self):
        src = "fn main() {\n    var x int = 1\n    fmt.println(\"{x}\")\n}\n"
        out = vf.mut_declare_extra_local(src, random.Random(1))
        self.assertTrue(out)
        self.assertIn("probe_value := 1", out[0])
        self.assertIn("_ = probe_value", out[0])


class OracleTests(unittest.TestCase):
    def test_accept_managed_normalises_to_accept(self):
        self.assertEqual(vf.expected_signature(("ACCEPT-MANAGED", None)), "accept")

    def test_rule_id_is_not_part_of_the_signature(self):
        # Two reject fixtures with different rules compare equal: a mutation may
        # legitimately reach a neighbouring rule without changing the verdict.
        self.assertEqual(
            vf.expected_signature(("REJECT", "BUILDABLE")),
            vf.expected_signature(("REJECT", "N1")),
        )


class DetectionTests(unittest.TestCase):
    """The tool must fire when the checker stops checking."""

    def test_a_weakened_checker_is_detected(self):
        # Stand-in checker: always accepts. Every REJECT fixture must flip.
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td)
            (corpus / "a-reject.hy").write_text(
                "// EXPECTED-VERDICT: REJECT BUILDABLE\n"
                "fn main() {\n    var x int = 1\n    fmt.println(\"hi\")\n}\n"
            )
            fake = corpus / "fake-hyb"
            # `--json` must report accept, and the source must still parse.
            fake.write_text(
                "#!/bin/sh\n"
                'echo \'{"summary":{"verdict":"accept"},"diagnostics":[]}\'\n'
            )
            fake.chmod(0o755)
            # main() reads argv; drive it through the module's own entry.
            import sys
            argv = sys.argv
            sys.argv = ["verdict_fuzz.py", "--bin", str(fake), "--corpus", str(corpus)]
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = vf.main()
            finally:
                sys.argv = argv
            out = buf.getvalue()
            self.assertEqual(rc, 1, out)
            # Every tried mutation must flip: this checker cannot reject at all,
            # so any non-zero count proves the detector fires. Asserting exactly
            # 1 would pin an operator count rather than the behaviour.
            self.assertIn("FLIP  a-reject.hy", out)
            self.assertNotIn("verdict flips     : 0", out)


if __name__ == "__main__":
    unittest.main()
