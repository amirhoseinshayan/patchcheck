"""Crash classification against real diagnostics recorded with the project toolchain.

Samples live in tests/unit/data/crashes/ and are re-recorded by record.sh from
crashzoo.c / crashzoo.cpp inside the patchcheck-framework image.
"""
import json
import unittest
from pathlib import Path

from patchcheck.analysis import analyze, parse_frame, reproduces
from patchcheck.replay import comparable

DATA = Path(__file__).resolve().parent / 'data' / 'crashes'
STATUS = json.loads((DATA / 'samples.json').read_text())


def run_for(name, **extra):
    status = STATUS[name]
    # ASan/UBSan samples were recorded from sanitized builds; release-* samples from
    # the normal build. analyze() now gates sanitizer parsing on build_type.
    build_type = 'sanitized' if name.startswith(('asan-', 'ubsan-')) else 'release'
    run = {'id': name, 'build_type': build_type,
           'exit_code': status if status < 128 else None, 'signal': status - 128 if status > 128 else None,
           'timeout': False, 'resource_status': 'ok', 'output_truncated': False, 'runner_error': None}
    run.update(extra)
    return run


def classify(name, **extra):
    return analyze(run_for(name, **extra), (DATA / f'{name}.txt').read_bytes())


# sample: (error type, detection method, termination, signature location or None, access kind)
EXPECTED = {
    'asan-heap': ('heap-buffer-overflow', 'asan', 'SIGABRT', 'crashzoo.c:heap_overflow', 'WRITE'),
    'asan-stack': ('stack-buffer-overflow', 'asan', 'SIGABRT', 'crashzoo.c:stack_pointer', 'WRITE'),
    'asan-uaf': ('use-after-free', 'asan', 'SIGABRT', 'crashzoo.c:use_after_free', 'WRITE'),
    'asan-double': ('double-free', 'asan', 'SIGABRT', 'crashzoo.c:double_free', None),
    'asan-global': ('global-buffer-overflow', 'asan', 'SIGABRT', 'crashzoo.c:global_overflow', 'READ'),
    'asan-cpp': ('heap-buffer-overflow', 'asan', 'SIGABRT',
                 'crashzoo.cpp:parser::Reader::copy(char const*, unsigned long)', 'WRITE'),
    'ubsan-null': ('null-pointer-dereference', 'ubsan', 'exit 1', 'crashzoo.c:null_deref', None),
    'ubsan-div': ('divide-by-zero', 'ubsan', 'exit 1', 'crashzoo.c:divide', None),
    'ubsan-index': ('array-index-out-of-bounds', 'ubsan', 'exit 1', 'crashzoo.c:array_index', None),
    'ubsan-objsize': ('object-size-overflow', 'ubsan', 'exit 1', 'crashzoo.c:stack_overflow', None),
    'release-heap': ('buffer-overflow', 'fortify-source', 'SIGABRT', None, None),
    'release-stack': ('stack-buffer-overflow', 'stack-protector', 'SIGABRT', None, None),
    'release-double': ('double-free', 'glibc-malloc-check', 'SIGABRT', None, None),
    'release-null': ('segmentation-fault', 'os-signal', 'SIGSEGV', None, None),
    'release-div': ('arithmetic-exception', 'os-signal', 'SIGFPE', None, None),
}


class RealDiagnosticsTests(unittest.TestCase):
    def test_every_recorded_sample_is_classified(self):
        self.assertEqual(set(EXPECTED), set(STATUS))
        for name, (error_type, method, ended, location, access) in EXPECTED.items():
            with self.subTest(sample=name):
                obs = classify(name)['observations'][0]
                self.assertEqual(obs['error_type'], error_type)
                self.assertEqual(obs['detection_method'], method)
                term = obs['termination']
                self.assertEqual(term['signal_name'] or f'exit {term["exit_code"]}', ended)
                self.assertEqual(obs['signature']['location'] if obs['signature'] else None, location)
                self.assertEqual((obs['access'] or {}).get('kind'), access)

    def test_detector_evidence_is_confirmed_bare_signals_are_not(self):
        for name in EXPECTED:
            with self.subTest(sample=name):
                result = classify(name)
                obs = result['observations'][0]
                bare = obs['detection_method'] == 'os-signal'
                self.assertEqual(obs['confirmation'], 'unclassified' if bare else 'confirmed')
                self.assertEqual(result['complete'], obs['signature'] is not None)
                self.assertIsNone(obs['root_cause'])

    def test_signature_key_is_access_kind_or_error_type(self):
        self.assertEqual(classify('asan-heap')['observations'][0]['signature'],
                         {'error_type': 'heap-buffer-overflow', 'location': 'crashzoo.c:heap_overflow', 'key': 'WRITE'})
        self.assertEqual(classify('asan-double')['observations'][0]['signature']['key'], 'double-free')

    def test_location_skips_sanitizer_runtime_frames(self):
        obs = classify('asan-heap')['observations'][0]
        self.assertEqual(obs['frames'][0]['function'], 'memset')
        self.assertIsNone(obs['frames'][0]['project_file'])
        self.assertEqual(obs['location']['function'], 'heap_overflow')
        self.assertEqual(obs['location']['file'], 'crashzoo.c')

    def test_related_allocation_and_free_stacks_are_kept(self):
        labels = [s['label'] for s in classify('asan-uaf')['observations'][0]['related_stacks']]
        self.assertEqual(labels, ['freed by thread T0 here', 'previously allocated by thread T0 here'])

    def test_truncated_stderr_makes_analysis_incomplete(self):
        result = classify('asan-heap', output_truncated=True)
        self.assertFalse(result['complete'])
        self.assertIn('truncated', result['reason'])


class TerminationTests(unittest.TestCase):
    def base_run(self, **extra):
        return {'id': 'r', 'exit_code': 0, 'signal': None, 'timeout': False, 'resource_status': 'ok',
                'output_truncated': False, 'runner_error': None, **extra}

    def test_normal_exits_have_no_observations(self):
        for code in (0, 2):
            result = analyze(self.base_run(exit_code=code), b'error: value too long\n')
            self.assertTrue(result['complete'])
            self.assertEqual(result['observations'], [])

    def test_timeout_and_resource_limits_are_separate_and_unconfirmed(self):
        obs = analyze(self.base_run(exit_code=None, signal=9, timeout=True), b'')['observations']
        self.assertEqual([o['error_type'] for o in obs], ['timeout'])
        self.assertEqual(obs[0]['confirmation'], 'unclassified')
        obs = analyze(self.base_run(exit_code=None, signal=9, resource_status='memory'), b'')['observations']
        self.assertEqual(obs[-1]['detection_method'], 'resource-limit')

    def test_runner_error_is_incomplete(self):
        result = analyze(self.base_run(runner_error='docker failed'), b'')
        self.assertFalse(result['complete'])

    def test_vague_corrupted_message_with_abort_is_unclassified_not_heap_corruption(self):
        # A program that prints a normal message containing "corrupted" and then
        # aborts must not be classified as a confirmed glibc heap-corruption.
        run = self.base_run(exit_code=None, signal=6)
        obs = analyze(run, b'error: configuration file corrupted, aborting\n')['observations'][0]
        self.assertEqual(obs['confirmation'], 'unclassified')
        self.assertEqual(obs['error_type'], 'abort')
        self.assertIsNone(obs['signature'])

    def test_glibc_corrupted_top_size_is_confirmed_heap_corruption(self):
        # glibc's exact heap-corruption diagnostic must be a confirmed finding
        # (glibc-malloc-check), not an unclassified bare abort. This is the release
        # build's detector for a heap write past a correctly-sized buffer.
        run = self.base_run(exit_code=None, signal=6)
        obs = analyze(run, b'malloc(): corrupted top size\n')['observations'][0]
        self.assertEqual(obs['confirmation'], 'confirmed')
        self.assertEqual(obs['error_type'], 'heap-corruption')
        self.assertEqual(obs['detection_method'], 'glibc-malloc-check')
        self.assertIsNone(obs['signature'])

    def test_asan_segv_on_zero_page_is_null_dereference(self):
        stderr = (b'==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x1 bp 0x2 sp 0x3 T0)\n'
                  b'==1==The signal is caused by a READ memory access.\n'
                  b'==1==Hint: address points to the zero page.\n'
                  b'    #0 0x55 in lookup /work/src/table.c:41\n    #1 0x56 in main /work/src/main.c:9\n')
        obs = analyze(self.base_run(exit_code=None, signal=6, build_type='sanitized'), stderr)['observations'][0]
        self.assertEqual(obs['error_type'], 'null-pointer-dereference')
        self.assertEqual(obs['access'], {'kind': 'READ', 'size': None})
        self.assertEqual(obs['signature']['location'], 'src/table.c:lookup')

    def test_release_record_with_sanitizer_text_is_not_a_confirmed_finding(self):
        # Review item 2: a release build whose stderr happens to carry ASan text must
        # not be classified as a confirmed sanitizer finding; it falls through to the
        # bare-signal path and stays unclassified.
        stderr = (b'==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n'
                  b'    #0 0x55 in f /work/src/a.c:3\n')
        obs = analyze(self.base_run(exit_code=None, signal=6, build_type='release'), stderr)['observations'][0]
        self.assertEqual(obs['confirmation'], 'unclassified')
        self.assertEqual(obs['detection_method'], 'os-signal')
        self.assertIsNone(obs['signature'])


class ReproducesTests(unittest.TestCase):
    SIGNATURE = {'error_type': 'heap-buffer-overflow', 'location': 'crashzoo.c:heap_overflow', 'key': 'WRITE'}

    def run_with(self, name, build):
        return {**run_for(name), 'build_type': build, 'analysis': classify(name)}

    def test_sanitized_build_needs_the_exact_signature(self):
        self.assertEqual(reproduces(self.SIGNATURE, self.run_with('asan-heap', 'sanitized')), 'match')
        self.assertEqual(reproduces(self.SIGNATURE, self.run_with('asan-uaf', 'sanitized')), 'mismatch')

    def test_release_build_without_location_is_unknown_not_a_blind_match(self):
        # A release build has no symbolized location, so even a confirmed detector
        # (FORTIFY "buffer overflow detected") cannot confirm it is the *same* bug
        # as the sanitized signature. It is recorded as unknown, never a blind match.
        self.assertEqual(reproduces(self.SIGNATURE, self.run_with('release-heap', 'release')), 'unknown')
        self.assertEqual(reproduces(self.SIGNATURE, self.run_with('release-null', 'release')), 'unknown')
        clean = {'build_type': 'release', 'analysis': {'observations': []}}
        self.assertEqual(reproduces(self.SIGNATURE, clean), 'unknown')

    def test_release_build_with_a_symbolized_location_matches_exactly(self):
        # If a release run somehow carries a location (e.g. a symbolized stack), the
        # exact signature comparison still applies.
        obs = classify('asan-heap')['observations'][0]
        symbolized = {'build_type': 'release', 'analysis': {'observations': [obs]}}
        self.assertEqual(reproduces(self.SIGNATURE, symbolized), 'match')


class FrameParsingTests(unittest.TestCase):
    def test_module_only_frame(self):
        frame = parse_frame('    #5 0x7ffffe91eca7  (/lib/x86_64-linux-gnu/libc.so.6+0x29ca7) (BuildId: 5e5b51f4)')
        self.assertEqual(frame['module'], '/lib/x86_64-linux-gnu/libc.so.6+0x29ca7')
        self.assertIsNone(frame['function'])

    def test_source_frame_with_column(self):
        frame = parse_frame('    #1 0x5555 in copy_value /work/lib/tlv.c:31:5')
        self.assertEqual((frame['function'], frame['file'], frame['line'], frame['project_file']),
                         ('copy_value', '/work/lib/tlv.c', 31, 'lib/tlv.c'))


class ReplayComparisonTests(unittest.TestCase):
    def test_classified_crash_ignores_address_noise_in_stderr(self):
        first = {**run_for('asan-heap'), 'stdout_sha256': 'x', 'stderr_sha256': 'aaa',
                 'analysis': classify('asan-heap')}
        second = {**first, 'stderr_sha256': 'bbb'}
        self.assertEqual(comparable(first), comparable(second))

    def test_unclassified_run_still_compares_stderr_bytes(self):
        first = {'exit_code': 2, 'stdout_sha256': 'x', 'stderr_sha256': 'aaa', 'analysis': {'observations': []}}
        self.assertNotEqual(comparable(first), comparable({**first, 'stderr_sha256': 'bbb'}))


if __name__ == '__main__':
    unittest.main()
