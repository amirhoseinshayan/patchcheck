"""Acceptance-gate decision logic (mirrors .github/workflows/patchcheck.yml gate).

The gate is deliberately conservative: only a complete, valid run whose reported
verdict matches the real exit code and equals 0 passes. Every other outcome
(10/20/30/40, a missing/corrupt report, an unknown exit code, or a mismatch)
fails, with the result type surfaced in the annotation.
"""
import json
import unittest
from pathlib import Path


def gate(actual, report_dir):
    """Return (exit_code, annotation_kind, message) for the acceptance check."""
    report = Path(report_dir) / 'report.json'
    if not report.exists():
        return 1, 'error', 'missing report.json (infrastructure or evaluation failure)'
    if actual not in (0, 10, 20, 30, 40):
        return 1, 'error', f'unknown patchcheck exit code: {actual}'
    try:
        reported = json.loads(report.read_text())['exit_code']
    except (ValueError, KeyError):
        return 1, 'error', 'corrupt report.json'
    if reported != actual:
        return 1, 'error', f'reported verdict {reported} != actual exit {actual}'
    return {
        0: (0, 'notice', 'VERDICT 0 - PASS: vulnerability fixed and functional preserved'),
        10: (10, 'error', 'VERDICT 10 - VULN_REMAINS/NEW_ISSUE: a confirmed security issue remains'),
        20: (20, 'error', 'VERDICT 20 - FUNC_REGRESSION: a valid input regressed'),
        30: (30, 'error', 'VERDICT 30 - BUILD_OR_CONFIG_ERROR'),
        40: (40, 'error', 'VERDICT 40 - INCONCLUSIVE (insufficient evidence / fixture)'),
    }[actual]


class GateTests(unittest.TestCase):
    def write_report(self, code):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        Path(self.tmp, 'report.json').write_text(json.dumps({'exit_code': code}))
        return self.tmp

    def test_verdict_zero_passes(self):
        d = self.write_report(0)
        self.assertEqual(gate(0, d)[0], 0)

    def test_verdicts_10_20_30_40_fail(self):
        for code, kind in ((10, 'VULN_REMAINS/NEW_ISSUE'), (20, 'FUNC_REGRESSION'),
                           (30, 'BUILD_OR_CONFIG_ERROR'), (40, 'INCONCLUSIVE')):
            d = self.write_report(code)
            exit_code, ann, msg = gate(code, d)
            self.assertEqual(exit_code, code)
            self.assertEqual(ann, 'error')
            self.assertIn(f'VERDICT {code}', msg)

    def test_missing_report_fails(self):
        import tempfile
        d = tempfile.mkdtemp()
        exit_code, ann, msg = gate(0, d)
        self.assertEqual(exit_code, 1)
        self.assertIn('missing report', msg)

    def test_corrupt_report_fails(self):
        import tempfile
        d = tempfile.mkdtemp()
        Path(d, 'report.json').write_text('not json')
        exit_code, ann, msg = gate(0, d)
        self.assertEqual(exit_code, 1)
        self.assertIn('corrupt report', msg)

    def test_unknown_exit_code_fails(self):
        d = self.write_report(0)
        exit_code, ann, msg = gate(7, d)
        self.assertEqual(exit_code, 1)
        self.assertIn('unknown patchcheck exit code', msg)

    def test_reported_actual_mismatch_fails(self):
        d = self.write_report(10)
        exit_code, ann, msg = gate(0, d)
        self.assertEqual(exit_code, 1)
        self.assertIn('!= actual exit', msg)


if __name__ == '__main__':
    unittest.main()
