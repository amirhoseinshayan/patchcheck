"""Patch correlation: source map, changed-line parsing and the relation rules."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from _tmp import tmpdir
from patchcheck.analysis import analyze, correlate
from patchcheck.source import parse_hunks
from patchcheck.sourcemap import annotate, function_spans, references, short_name

ROOT = Path(__file__).resolve().parents[2]
TLV = ROOT / 'targets' / 'tlvparse'


class FunctionSpanTests(unittest.TestCase):
    def spans(self, text):
        return [(s['name'], s['start'], s['end']) for s in function_spans(text)]

    def test_c_definitions_ignore_comments_strings_structs_and_initializers(self):
        code = '\n'.join([
            '#include <stdio.h>',                       # 1
            'struct point { int x; int y; };',          # 2
            'static int table[] = { 1, 2, 3 };',        # 3
            '/* not() { a function } */',               # 4
            'static int',                               # 5
            'add(int a, int b)',                        # 6
            '{',                                        # 7
            '    const char *s = "}{";',                # 8
            "    char c = '}';",                        # 9
            '    if (a) { return b; }',                 # 10
            '    return a + b;',                        # 11
            '}',                                        # 12
            '__attribute__((noinline)) void f(void) { // }',  # 13
            '}',                                        # 14
            '#define BLOCK { }',                        # 15
            'struct point *make(void) { return 0; }',   # 16
        ])
        self.assertEqual(self.spans(code), [('add', 5, 12), ('f', 13, 14), ('make', 16, 16)])

    def test_cpp_namespaces_classes_and_qualified_methods(self):
        code = '\n'.join([
            'namespace parser {',                                  # 1
            'class Reader {',                                      # 2
            ' public:',                                            # 3
            '  void copy(const char *src, unsigned long n) {',     # 4
            '    buf_[0] = src[0];',                               # 5
            '  }',                                                 # 6
            '  char buf_[4];',                                     # 7
            '};',                                                  # 8
            'int Reader2::size() const { return 1; }',             # 9
            '}  // namespace parser',                              # 10
            'extern "C" {',                                        # 11
            'int c_api(void) { return 0; }',                       # 12
            '}',                                                   # 13
        ])
        self.assertEqual(self.spans(code), [('parser::Reader::copy', 4, 6), ('parser::Reader2::size', 9, 9), ('c_api', 12, 12)])

    def test_short_name_of_symbolized_frames(self):
        self.assertEqual(short_name('parser::Reader::copy(char const*, unsigned long)'), 'copy')
        self.assertEqual(short_name('copy_value'), 'copy_value')
        self.assertEqual(short_name('std::vector<int>::push_back(int const&)'), 'push_back')


class HunkParsingTests(unittest.TestCase):
    def test_changed_lines_skip_context_comments_and_header_lookalikes(self):
        diff = (b'diff --git a/p.c b/p.c\n--- a/p.c\n+++ b/p.c\n'
                b'@@ -1,5 +1,6 @@\n'
                b' int x;\n'
                b'--- y;\n'                 # a removed line whose text is "-- y;"
                b'+#define LIMIT 31\n'
                b'+/* explain */\n'
                b'+\n'
                b'+y--;\n'
                b' z;\n'
                b' w;\n')
        hunk = parse_hunks(diff)[0]
        self.assertEqual((hunk['file'], hunk['removed'], hunk['added']), ('p.c', [2], [2, 5]))
        self.assertEqual(hunk['defines'], ['LIMIT'])
        self.assertEqual(hunk['define_lines'], {'base': [], 'candidate': [2]})


def tlv_diff(version):
    """Real diff and source map between targets/tlvparse/base and another version."""
    with tmpdir() as tmp:
        shutil.copytree(TLV / 'base', tmp / 'a')
        shutil.copytree(TLV / version, tmp / 'b')
        raw = subprocess.run(['git', 'diff', '--no-index', '--src-prefix=', '--dst-prefix=', 'a/tlvparse.c',
                              'b/tlvparse.c'], cwd=tmp, capture_output=True).stdout
        hunks = parse_hunks(raw)
        return {'hunks': hunks, 'source_map': annotate(hunks, tmp / 'a', tmp / 'b')}


class SourceMapTests(unittest.TestCase):
    def test_tlvparse_hunks_map_to_functions_and_callers(self):
        diff = tlv_diff('incomplete')
        self.assertEqual({(c['version'], c['function']) for c in diff['hunks'][0]['functions']},
                         {('base', 'load_name'), ('candidate', 'load_name')})
        self.assertFalse(diff['hunks'][0]['unmapped'])
        self.assertEqual(diff['source_map']['base']['callers']['load_name'],
                         [{'file': 'tlvparse.c', 'function': 'parse'}])
        diff = tlv_diff('correct')
        self.assertEqual({(c['version'], c['function']) for c in diff['hunks'][0]['functions']},
                         {('base', 'copy_value'), ('candidate', 'copy_value')})


class MacroUseTests(unittest.TestCase):
    def test_macro_name_in_comment_or_string_is_not_a_use(self):
        with tmpdir() as tmp:
            (tmp / 'p.c').write_text(
                'int f(void) {\n'
                '    /* MAX_VALUE is the limit */\n'
                '    const char *s = "MAX_VALUE";\n'
                '    return 0;\n'
                '}\n'
                'int g(void) {\n'
                '    return MAX_VALUE;\n'
                '}\n')
            (tmp / 'h.h').write_text('#define MAX_VALUE 32\n')
            _, users = references(tmp, set(), {'MAX_VALUE'})
        self.assertEqual(users['MAX_VALUE'], [{'file': 'p.c', 'function': 'g'}])

    def test_macro_in_preprocessor_condition_is_a_use(self):
        with tmpdir() as tmp:
            (tmp / 'p.c').write_text(
                'int f(void) {\n'
                '#if defined(MAX_VALUE)\n'
                '    return MAX_VALUE;\n'
                '#else\n'
                '    return 0;\n'
                '#endif\n'
                '}\n')
            _, users = references(tmp, set(), {'MAX_VALUE'})
        self.assertEqual(users['MAX_VALUE'], [{'file': 'p.c', 'function': 'f'}])


# --- relation rules ----------------------------------------------------------

def asan_stack(*functions, file='tlvparse.c'):
    """Real-format ASan heap overflow report whose stack is the given functions (innermost first)."""
    frames = ''.join(f'    #{i + 1} 0x55{i} in {name} /work/{file}:{10 * (i + 1)}\n' for i, name in enumerate(functions))
    return (b'==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6 at pc 0x1 bp 0x2 sp 0x3\n'
            b'WRITE of size 100 at 0x6 thread T0\n'
            b'    #0 0x7f in __asan_memcpy (/usr/lib/libasan.so.8+0xfa)\n' + frames.encode() +
            b'\n0x6 is located 0 bytes after 32-byte region\nallocated by thread T0 here:\n'
            b'    #0 0x7f in malloc (/usr/lib/libasan.so.8+0xfb)\n' +
            f'    #1 0x55 in {functions[0]} /work/{file}:5\n'.encode() + b'\nSUMMARY: AddressSanitizer: x\n')


def run(run_id, version, build='sanitized', stderr=None):
    record = {'id': run_id, 'version': version, 'build_type': build, 'exit_code': None if stderr else 0,
              'signal': 6 if stderr else None, 'timeout': False, 'resource_status': 'ok',
              'output_truncated': False, 'runner_error': None}
    record['analysis'] = analyze(record, stderr or b'')
    return record


def hunk(function, *, unmapped=False, defines=(), file='tlvparse.c', added=(12,), removed=()):
    return {'id': 'h1', 'file': file, 'old_file': file, 'removed': list(removed), 'added': list(added),
            'defines': list(defines), 'define_lines': {'base': [], 'candidate': []}, 'unmapped': unmapped,
            'functions': [{'version': side, 'file': file, 'function': function, 'short': function,
                           'start': 5, 'end': 25} for side in ('base', 'candidate')] if function else []}


def relate(status, base, candidate, hunks, graph=None, finding_id='f-sanitized'):
    graph = graph or {'base': {'callers': {}, 'macro_users': {}}, 'candidate': {'callers': {}, 'macro_users': {}}}
    finding = {'id': finding_id, 'status': status, 'base_run_ids': [base['id']], 'candidate_run_ids': [candidate['id']]}
    return correlate({'hunks': hunks, 'source_map': graph}, [finding], [base, candidate])[0]


PATH = ('copy_value', 'load_blob', 'parse', 'main')


class RelationTests(unittest.TestCase):
    def test_crash_site_on_changed_line_is_confirmed(self):
        # The crashing frame line (10) is itself a changed line (removed on the
        # base side for a Fixed finding): a direct data/control-flow link, the only
        # static evidence that confirms.
        rel = relate('Fixed', run('b', 'base', stderr=asan_stack(*PATH)), run('c', 'candidate'),
                     [hunk('copy_value', removed=(10,))])
        self.assertEqual(rel['relation'], 'confirmed')
        self.assertEqual(rel['hunk_ids'], ['h1'])
        self.assertIn('crash-site', {l['role'] for l in rel['locations']})

    def test_fix_in_the_crash_site_function_is_candidate(self):
        # The changed function is the crash site, but the crashing line is not a
        # changed line: presence on the stack is only a candidate, never confirmed.
        rel = relate('Fixed', run('b', 'base', stderr=asan_stack(*PATH)), run('c', 'candidate'),
                     [hunk('copy_value')])
        self.assertEqual(rel['relation'], 'candidate')
        self.assertIn('crash-site', {l['role'] for l in rel['locations']})

    def test_fix_in_a_caller_is_candidate(self):
        rel = relate('Fixed', run('b', 'base', stderr=asan_stack(*PATH)), run('c', 'candidate'),
                     [hunk('load_blob')])
        self.assertEqual(rel['relation'], 'candidate')
        self.assertEqual([l['role'] for l in rel['locations']], ['caller'])

    def test_fix_off_the_stack_is_unknown_not_rejected(self):
        rel = relate('Fixed', run('b', 'base', stderr=asan_stack(*PATH)), run('c', 'candidate'),
                     [hunk('load_name')])
        self.assertEqual(rel['relation'], 'unknown')

    def test_incomplete_fix_off_the_failing_path_is_unknown_with_sibling_evidence(self):
        # A changed function that is only a callee of the failing path is *not* on
        # the stack; a function may have run and returned earlier, so the relation
        # cannot be rejected from the stack alone. It is reported unknown.
        graph = {v: {'callers': {'load_name': [{'file': 'tlvparse.c', 'function': 'parse'}]}, 'macro_users': {}}
                 for v in ('base', 'candidate')}
        crash = asan_stack(*PATH)
        rel = relate('Incomplete Fix', run('b', 'base', stderr=crash), run('c', 'candidate', stderr=crash),
                     [hunk('load_name')], graph)
        self.assertEqual(rel['relation'], 'unknown')
        self.assertEqual([l['role'] for l in rel['locations']], ['callee-of-path'])

    def test_rejection_needs_complete_stack_and_mapped_hunks(self):
        partial = asan_stack('copy_value', 'load_blob')        # does not reach main
        rel = relate('Incomplete Fix', run('b', 'base', stderr=partial), run('c', 'candidate', stderr=partial),
                     [hunk('load_name')])
        self.assertEqual(rel['relation'], 'unknown')
        crash = asan_stack(*PATH)
        rel = relate('Incomplete Fix', run('b', 'base', stderr=crash), run('c', 'candidate', stderr=crash),
                     [hunk(None, unmapped=True)])
        self.assertEqual(rel['relation'], 'unknown')

    def test_incomplete_fix_touching_the_path_is_candidate(self):
        crash = asan_stack(*PATH)
        rel = relate('Incomplete Fix', run('b', 'base', stderr=crash), run('c', 'candidate', stderr=crash),
                     [hunk('load_blob')])
        self.assertEqual(rel['relation'], 'candidate')

    def test_new_issue_uses_the_candidate_stack_and_is_candidate(self):
        rel = relate('New Issue', run('b', 'base'), run('c', 'candidate', stderr=asan_stack(*PATH)),
                     [hunk('copy_value')])
        self.assertEqual(rel['relation'], 'candidate')
        self.assertEqual({l['version'] for l in rel['locations']}, {'candidate'})

    def test_changed_macro_used_on_the_stack_is_candidate(self):
        graph = {v: {'callers': {}, 'macro_users': {'MAX_VALUE': [{'file': 'tlvparse.c', 'function': 'copy_value'}]}}
                 for v in ('base', 'candidate')}
        rel = relate('Fixed', run('b', 'base', stderr=asan_stack(*PATH)), run('c', 'candidate'),
                     [hunk(None, defines=['MAX_VALUE'])], graph)
        self.assertEqual(rel['relation'], 'candidate')
        self.assertEqual(rel['locations'][0]['role'], 'uses-changed-macro')

    def test_release_without_stack_stays_unknown_and_points_to_sanitized_pair(self):
        hunks = [hunk('copy_value')]
        graph = {v: {'callers': {}, 'macro_users': {}} for v in ('base', 'candidate')}
        release = run('br', 'base', 'release', stderr=b'*** buffer overflow detected ***: terminated\n')
        sanitized = run('bs', 'base', stderr=asan_stack(*PATH))
        findings = [{'id': 'f-release', 'status': 'Fixed', 'base_run_ids': ['br'], 'candidate_run_ids': ['cr']},
                    {'id': 'f-sanitized', 'status': 'Fixed', 'base_run_ids': ['bs'], 'candidate_run_ids': ['cs']}]
        rels = correlate({'hunks': hunks, 'source_map': graph}, findings,
                         [release, sanitized, run('cr', 'candidate', 'release'), run('cs', 'candidate')])
        self.assertEqual([r['relation'] for r in rels], ['unknown', 'candidate'])
        self.assertIn('f-sanitized is candidate', rels[0]['evidence'][-1])

    def test_functional_regression_and_missing_source_map_are_unknown(self):
        rel = relate('Functional Regression', run('b', 'base'), run('c', 'candidate'), [hunk('copy_value')])
        self.assertEqual(rel['relation'], 'unknown')
        old = correlate({'hunks': [{'id': 'h1', 'file': 'p.c'}]}, [{'id': 'f', 'status': 'Fixed'}], [])[0]
        self.assertEqual(old['relation'], 'unknown')


if __name__ == '__main__':
    unittest.main()
