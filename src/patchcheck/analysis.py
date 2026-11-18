"""Crash analysis: classify how a run failed from its real termination and stderr.

`analyze` keeps four things apart, as the assignment requires:
  * error type        what went wrong (heap-buffer-overflow, use-after-free, ...)
  * detection method  who noticed (asan, ubsan, fortify-source, stack-protector,
                      glibc-malloc-check, os-signal, time-limit, resource-limit)
  * termination       how the process ended (exit code / signal / timeout / limit)
  * location          first stack frame inside the program's own source
Root cause is never inferred here. A bare signal without detector evidence is
recorded as `unclassified`, never as a confirmed vulnerability.
"""
import re

from .coverage import covered_changes
from .sourcemap import qualified_name, short_name

PROJECT_PREFIX = '/work/'  # build.py compiles every target inside /work
MAX_FRAMES = 32

SIGNALS = {4: 'SIGILL', 5: 'SIGTRAP', 6: 'SIGABRT', 7: 'SIGBUS', 8: 'SIGFPE', 9: 'SIGKILL',
           11: 'SIGSEGV', 13: 'SIGPIPE', 15: 'SIGTERM', 24: 'SIGXCPU', 25: 'SIGXFSZ'}

# Bare signals: what the OS tells us when no detector printed anything.
SIGNAL_TYPES = {'SIGSEGV': 'segmentation-fault', 'SIGBUS': 'bus-error', 'SIGFPE': 'arithmetic-exception',
                'SIGILL': 'illegal-instruction', 'SIGABRT': 'abort', 'SIGTRAP': 'trap'}

# AddressSanitizer report kinds, matched against the text after "AddressSanitizer: ".
ASAN_TYPES = [
    ('heap-use-after-free', 'use-after-free'),
    ('attempting double-free', 'double-free'),
    ('attempting free on address which was not malloc()-ed', 'invalid-free'),
    ('alloc-dealloc-mismatch', 'alloc-dealloc-mismatch'),
    ('heap-buffer-overflow', 'heap-buffer-overflow'),
    ('stack-buffer-overflow', 'stack-buffer-overflow'),
    ('stack-buffer-underflow', 'stack-buffer-underflow'),
    ('dynamic-stack-buffer-overflow', 'stack-buffer-overflow'),
    ('global-buffer-overflow', 'global-buffer-overflow'),
    ('stack-use-after-return', 'stack-use-after-return'),
    ('stack-use-after-scope', 'stack-use-after-scope'),
    ('container-overflow', 'container-overflow'),
    ('stack-overflow', 'stack-exhaustion'),
    ('negative-size-param', 'negative-size-param'),
    ('memcpy-param-overlap', 'memcpy-param-overlap'),
    ('requested allocation size', 'allocation-size-too-big'),
    ('allocation-size-too-big', 'allocation-size-too-big'),
    ('out of memory', 'out-of-memory'),
    ('FPE', 'arithmetic-exception'),
    ('SEGV', 'segmentation-fault'),  # refined below to null / wild access
    ('BUS', 'bus-error'),
]

# UndefinedBehaviorSanitizer "runtime error:" messages.
UBSAN_TYPES = [
    (r'division by zero', 'divide-by-zero'),
    (r'null pointer', 'null-pointer-dereference'),
    (r'out of bounds for type', 'array-index-out-of-bounds'),
    (r'insufficient space for an object', 'object-size-overflow'),
    (r'signed integer overflow', 'integer-overflow'),
    (r'shift exponent|left shift', 'invalid-shift'),
    (r'misaligned address', 'misaligned-access'),
    (r'pointer overflow|applying (non-)?zero offset', 'pointer-overflow'),
    (r'is not a valid value for type', 'invalid-value-load'),
    (r'unreachable program point', 'unreachable-reached'),
    (r'variable length array bound', 'invalid-vla-bound'),
    (r'is outside the range of representable values', 'float-cast-overflow'),
]

# glibc and compiler-inserted checks that abort the release build. Patterns are
# restricted to the exact messages glibc prints; a vague word such as "corrupted"
# is never enough on its own, otherwise a program that prints a normal message
# containing that word and then aborts would be misclassified as heap corruption.
LIBC_CHECKS = [
    (r'\*\*\* stack smashing detected \*\*\*', 'stack-buffer-overflow', 'stack-protector', '__stack_chk_fail'),
    (r'\*\*\* buffer overflow detected \*\*\*', 'buffer-overflow', 'fortify-source', '__chk_fail'),
    (r'double free', 'double-free', 'glibc-malloc-check', 'glibc malloc'),
    (r'free\(\): invalid (pointer|size)|munmap_chunk\(\): invalid pointer', 'invalid-free', 'glibc-malloc-check', 'glibc malloc'),
    (r'malloc\(\): memory corruption|malloc\(\): corrupted top size|'
     r'malloc\(\): corrupted unsorted chunks|malloc\(\): invalid size \(unsorted\)|'
     r'corrupted size vs\. prev_size|corrupted double-linked list|invalid next size|'
     r'unsorted double linked list corrupted|smallbin double linked list corrupted|'
     r'unaligned tcache chunk|invalid (fastbin|tcache)',
     'heap-corruption', 'glibc-malloc-check', 'glibc malloc'),
]

ASAN_HEADER = re.compile(r'==\d+==ERROR: AddressSanitizer: (.*)')
UBSAN_LINE = re.compile(r'^(?P<file>[^\s:][^:]*):(?P<line>\d+):(?P<col>\d+): runtime error: (?P<msg>.*)$')
FRAME = re.compile(r'^\s*#(\d+) 0x[0-9a-fA-F]+\s*(?:in )?(.*)$')
MODULE = re.compile(r'\s*\(([^()\s]+\+0x[0-9a-fA-F]+)\)$')
FILE_LINE = re.compile(r'(?:^|\s)(\S+?):(\d+)(?::\d+)?$')
ACCESS = re.compile(r'^(READ|WRITE) of size (\d+)')
SEGV_ADDRESS = re.compile(r'SEGV on unknown address (?:0x)?([0-9a-fA-F]+)')


def project_file(path):
    """Source-relative path for files of the program itself, else None."""
    if not path:
        return None
    if path.startswith(PROJECT_PREFIX):
        return path[len(PROJECT_PREFIX):]
    if path.startswith(('/', '../', '<')):
        return None
    return path[2:] if path.startswith('./') else path


def parse_frame(line):
    match = FRAME.match(line)
    if not match:
        return None
    rest = re.sub(r'\s*\(BuildId: [0-9a-fA-F]+\)\s*$', '', match[2]).strip()
    frame = {'index': int(match[1]), 'function': None, 'file': None, 'line': None, 'module': None}
    module = MODULE.search(rest)
    if module:
        frame['module'] = module[1]
        rest = rest[:module.start()].strip()
    else:
        location = FILE_LINE.search(rest)
        if location:
            frame['file'], frame['line'] = location[1], int(location[2])
            rest = rest[:location.start()].strip()
    frame['function'] = rest or None
    frame['project_file'] = project_file(frame['file'])
    return frame


def read_stacks(lines, start):
    """Stacks after line `start`: the first unlabelled one is where the error
    happened; stacks under "... here:" headings (allocated/freed by) are related."""
    stacks, current, label = [], None, None
    for line in lines[start:]:
        frame = parse_frame(line)
        if frame:
            if current is None:
                current = []
                stacks.append((label, current))
                label = None
            if len(current) < MAX_FRAMES:
                current.append(frame)
            continue
        current = None
        stripped = line.strip()
        if stripped.endswith('here:'):
            label = stripped[:-1].strip()
        elif stripped.endswith('in frame'):
            label = 'frame of the accessed stack variable'
        elif stripped.startswith('SUMMARY:'):
            break
    primary = stacks[0][1] if stacks and stacks[0][0] is None else []
    related = [{'label': name or 'stack', 'frames': frames} for name, frames in stacks if frames is not primary]
    return primary, related


def crash_location(frames):
    for frame in frames:
        if frame['project_file'] and frame['function']:
            return {'file': frame['project_file'], 'function': frame['function'], 'line': frame['line']}
    return None


def termination(run):
    signal = run.get('signal')
    if run.get('runner_error'):
        kind = 'runner-error'
    elif run.get('timeout'):
        kind = 'timeout'
    elif run.get('resource_status') not in (None, 'ok'):
        kind = 'resource-limit'
    elif signal:
        kind = 'signal'
    else:
        kind = 'exit'
    return {'kind': kind, 'exit_code': run.get('exit_code'), 'signal': signal,
            'signal_name': SIGNALS.get(signal, f'signal {signal}') if signal else None,
            'timeout': bool(run.get('timeout')), 'resource_status': run.get('resource_status'),
            'output_truncated': bool(run.get('output_truncated'))}


def observation(run, error_type, method, detector, message, *, frames=(), related=(), access=None,
                location=None, confirmed=True):
    location = location or crash_location(frames)
    signature = None
    if confirmed and location and location.get('function'):
        signature = {'error_type': error_type, 'location': f'{location["file"]}:{location["function"]}',
                     'key': access['kind'] if access else error_type}
    return {'run_id': run.get('id'), 'error_type': error_type, 'detection_method': method, 'detector': detector,
            'message': message, 'access': access, 'location': location, 'frames': list(frames),
            'related_stacks': list(related), 'termination': termination(run),
            'confirmation': 'confirmed' if confirmed else 'unclassified', 'signature': signature,
            'complete_evidence': signature is not None, 'root_cause': None}


def asan_observation(run, lines, index, text):
    kind = ASAN_HEADER.match(lines[index].strip())[1]
    error_type = next((name for prefix, name in ASAN_TYPES if kind.startswith(prefix)), 'memory-error')
    access = None
    for line in lines[index + 1:index + 4]:
        match = ACCESS.match(line.strip())
        if match:
            access = {'kind': match[1], 'size': int(match[2])}
            break
    if error_type == 'segmentation-fault':
        address = SEGV_ADDRESS.search(kind)
        if 'address points to the zero page' in text or (address and int(address[1], 16) < 0x1000):
            error_type = 'null-pointer-dereference'
        else:
            error_type = 'wild-memory-access'
        cause = re.search(r'caused by a (READ|WRITE) memory access', text)
        access = {'kind': cause[1], 'size': None} if cause else None
    frames, related = read_stacks(lines, index + 1)
    return observation(run, error_type, 'asan', 'AddressSanitizer', lines[index].strip(),
                       frames=frames, related=related, access=access)


def ubsan_observation(run, lines, index):
    match = UBSAN_LINE.match(lines[index].strip())
    error_type = next((name for pattern, name in UBSAN_TYPES if re.search(pattern, match['msg'])),
                      'undefined-behavior')
    frames, _ = read_stacks(lines, index + 1)
    location = crash_location(frames)
    if location is None and project_file(match['file']):
        location = {'file': project_file(match['file']), 'function': None, 'line': int(match['line'])}
    return observation(run, error_type, 'ubsan', 'UndefinedBehaviorSanitizer', lines[index].strip(),
                       frames=frames, location=location)


def analyze(run_record, stderr=b''):
    """Classify one run. Returns {complete, observations, reason}.

    `complete` is True when the run ended normally, or when every abnormal
    outcome has detector evidence with a type and an in-program location.
    """
    run = run_record
    if run.get('runner_error'):
        return {'complete': False, 'observations': [], 'reason': f'runner error: {run["runner_error"]}'}
    text = stderr.decode('utf-8', errors='replace') if isinstance(stderr, bytes) else str(stderr or '')
    lines = text.splitlines()
    observations = []

    # 1. Sanitizer reports (sanitized builds only). The first report is the one
    # that stopped the program. A release build is never classified from raw
    # ASan/UBSan text: if such text appears there anyway, it falls through to the
    # libc-check and bare-signal paths below, which record it as unclassified
    # rather than as a confirmed sanitizer finding (review item 2).
    if run.get('build_type') == 'sanitized':
        for index, line in enumerate(lines):
            if ASAN_HEADER.match(line.strip()):
                obs = asan_observation(run, lines, index, text)
                if not obs['frames'] or (run.get('exit_code') == 0 and not obs['signature']):
                    obs.update(confirmation='unclassified', complete_evidence=False, signature=None)
                observations.append(obs)
                break
            if UBSAN_LINE.match(line.strip()):
                obs = ubsan_observation(run, lines, index)
                if not obs['frames'] and run.get('exit_code') == 0:
                    obs.update(confirmation='unclassified', complete_evidence=False, signature=None)
                observations.append(obs)
                break

    # 2. Compiler/glibc checks that abort a release build.
    if not observations and run.get('signal') == 6:
        for pattern, error_type, method, detector in LIBC_CHECKS:
            match = re.search(pattern, text)
            if match:
                message = next(l.strip() for l in lines if re.search(pattern, l))
                observations.append(observation(run, error_type, method, detector, message))
                break

    # 3. A signal with no detector output: recorded, but never confirmed.
    signal = run.get('signal')
    if not observations and signal and not run.get('timeout'):
        name = SIGNALS.get(signal, f'signal {signal}')
        observations.append(observation(run, SIGNAL_TYPES.get(name, 'killed-by-signal'), 'os-signal', name,
                                         f'terminated by {name} without detector output', confirmed=False))

    # 4. Time and resource limits are reported separately from crashes.
    if run.get('timeout'):
        observations.append(observation(run, 'timeout', 'time-limit', 'wall/cpu limit',
                                        'execution exceeded the configured time limit', confirmed=False))
    elif run.get('resource_status') not in (None, 'ok'):
        observations.append(observation(run, 'resource-limit', 'resource-limit', str(run['resource_status']),
                                        f'resource limit reached: {run["resource_status"]}', confirmed=False))

    if not observations:
        return {'complete': True, 'observations': [],
                'reason': f'normal termination with exit code {run.get("exit_code")}'}
    complete = all(o['complete_evidence'] for o in observations)
    first = observations[0]
    where = first['signature']['location'] if first['signature'] else 'no in-program location'
    reason = f'{first["error_type"]} detected by {first["detection_method"]} ({where})'
    if run.get('output_truncated'):
        for obs in observations:
            obs.update(confirmation='unclassified', complete_evidence=False, signature=None)
        complete, reason = False, reason + '; stderr truncated'
    return {'complete': complete, 'observations': observations, 'reason': reason}


def security_observation(run):
    """The detector-backed failure of a run (fixture marker for fixtures), or None."""
    analysis = run.get('analysis') or {}
    if analysis.get('fixture_observation'):
        return analysis['fixture_observation']
    return next((o for o in analysis.get('observations', []) if o.get('confirmation') == 'confirmed'), None)


def uncertain_observation(run):
    """An abnormal end without detector evidence (bare signal, timeout, limit)."""
    analysis = run.get('analysis') or {}
    return next((o for o in analysis.get('observations', []) if o.get('confirmation') == 'unclassified'), None)


def same_failure(expected, observed):
    """match / mismatch / unknown between two observed failures.

    Signatures (type, file:function, access) are compared when both exist.
    Release builds have no in-program location, so there the error type and
    detector must agree instead.
    """
    if expected.get('signature') and observed.get('signature'):
        return match_failure(expected['signature'], observed)
    if expected.get('confirmation') == observed.get('confirmation') == 'confirmed':
        same = (expected['error_type'], expected['detection_method']) == \
               (observed['error_type'], observed['detection_method'])
        return 'match' if same else 'mismatch'
    return 'unknown'


def reproduces(expected_signature, run):
    """match / mismatch / unknown: does this run show the expected failure?

    A sanitized build (and a fixture) carries an in-program location, so it is
    matched exactly against the expected signature. A release build without a
    symbolized location cannot confirm it is the *same* bug (a detector such as
    FORTIFY only reports that some memory write overflowed), so such a run is
    `unknown` and never a blind `match`. Release evidence stays separate from the
    sanitized signature.
    """
    return match_failure(expected_signature, security_observation(run))


def fixture_observation(run, stderr):
    """Harmless fixture-only protocol, never a real security confirmation."""
    if (run.get('runner_error') or run.get('timeout') or run.get('output_truncated')
            or run.get('resource_status') != 'ok'):
        return None
    match = re.search(rb'^FIXTURE_FAILURE:([A-Z_]+):([a-z-]+)$', stderr, re.MULTILINE)
    if not match:
        return None
    return {'signature': {'error_type': 'fixture-marker', 'location': match[2].decode(),
                          'key': match[1].decode()}, 'confirmation': 'fixture', 'complete_evidence': True}


def match_failure(expected_signature, observed_finding):
    if not expected_signature or not observed_finding or not observed_finding.get('complete_evidence'):
        return 'unknown'
    observed = observed_finding.get('signature')
    keys = ('error_type', 'location', 'key')
    if not observed or any(not observed.get(k) or observed[k] == 'unknown' for k in keys):
        return 'unknown'
    if any(not expected_signature.get(k) or expected_signature[k] == 'unknown' for k in keys):
        return 'unknown'
    return 'match' if all(expected_signature[k] == observed[k] for k in keys) else 'mismatch'


# --- Patch correlation -------------------------------------------------------
#
# A relation links one finding to the diff hunks, using the stack of the failing
# run (crash site, callers, allocation/free stacks) and the static source map
# that source.py stored with the diff. Changed-line proximity is reported but
# never decides anything.
#
#   confirmed  a changed function (or a function using a changed macro) is on
#              the failing stack, and the paired base/candidate runs on the same
#              input agree with the finding status;
#   unknown    anything else (no stack, release build, unmapped hunks, a fix
#              that may act through code that returned before the crash, ...).
#              A stack that reaches main still does not record functions that ran
#              and returned earlier, so absence from the stack never *rejects* a
#              relation on its own.

PATH_ROLES = ('crash-site', 'caller', 'allocation-stack', 'free-stack', 'related-stack', 'uses-changed-macro')
LIMITATION = ('Static stack/source-map evidence from one input pair. Code that ran and returned before '
              'the crash is not on the stack; full causality would need coverage or a debugger trace.')


def stack_function(frame):
    return short_name(frame.get('function'))


def related_role(label):
    label = label.lower()
    return 'free-stack' if 'freed' in label else 'allocation-stack' if 'allocated' in label else 'related-stack'


def failing_stacks(run):
    """(observation, [(role, frame index, frame)]) for the detector-backed failure of a run."""
    obs = security_observation(run)
    if not obs or obs.get('confirmation') != 'confirmed' or not obs.get('frames'):
        return obs, []
    path, seen_site = [], False
    for frame in obs['frames']:
        if frame.get('project_file') and frame.get('function'):
            path.append(('caller' if seen_site else 'crash-site', frame['index'], frame))
            seen_site = True
    for stack in obs.get('related_stacks', []):
        for frame in stack['frames']:
            if frame.get('project_file') and frame.get('function'):
                path.append((related_role(stack['label']), frame['index'], frame))
    return obs, path


def stack_complete(obs):
    """The primary stack reaches main (or libc start), so absence from it is meaningful."""
    names = [stack_function(f) for f in obs.get('frames', [])]
    return 'main' in names or any('__libc_start' in (f.get('function') or '') for f in obs.get('frames', []))


def path_locations(version, path, hunks, graph):
    """Hunks whose changed function / macro meets the failing stack of `version`."""
    locations = []
    users = graph.get(version, {}).get('macro_users', {})
    for role, index, frame in path:
        name, file = qualified_name(frame.get('function')), frame['project_file']
        line = frame.get('line')
        for hunk in hunks:
            for changed in hunk.get('functions', []):
                if (changed['version'] == version and changed['file'] == file
                        and qualified_name(changed['function']) == name and line is not None
                        and changed['start'] <= line <= changed['end']):
                    side = hunk.get('removed' if version == 'base' else 'added', [])
                    locations.append({'hunk_id': hunk['id'], 'file': file, 'function': changed['function'],
                                      'version': version, 'role': role, 'frame_index': index,
                                      'line': frame.get('line'),
                                      'on_changed_line': line in side})
                    break
            for macro in hunk.get('defines', []):
                if any(u['file'] == file and qualified_name(u['function']) == name for u in users.get(macro, [])):
                    locations.append({'hunk_id': hunk['id'], 'file': file, 'function': frame['function'],
                                      'version': version, 'role': 'uses-changed-macro', 'macro': macro,
                                      'frame_index': index, 'line': frame.get('line'), 'on_changed_line': False})
    unique = []
    for location in locations:
        if location not in unique:
            unique.append(location)
    return unique


def sibling_locations(version, path, hunks, graph):
    """Changed functions called from a stack function but not on the stack themselves."""
    on_stack = {(f['project_file'], stack_function(f)) for _, _, f in path}
    callers = graph.get(version, {}).get('callers', {})
    found = []
    for hunk in hunks:
        for changed in hunk.get('functions', []):
            if (changed['file'], changed['short']) in on_stack:
                continue
            for caller in callers.get(changed['short'], []):
                if (caller['file'], stack_function(caller)) in on_stack:
                    entry = {'hunk_id': hunk['id'], 'file': changed['file'], 'function': changed['function'],
                             'version': version, 'role': 'callee-of-path', 'called_from': caller['function']}
                    if entry not in found:
                        found.append(entry)
    return found


def describe(location):
    where = f'{location["file"]}:{location["function"]}'
    if location['role'] == 'callee-of-path':
        return f'{location["hunk_id"]} changes {where}, called from {location["called_from"]} on the stack ' \
               f'but not itself on the failing stack'
    if location['role'] == 'uses-changed-macro':
        return f'{location["hunk_id"]} changes macro {location["macro"]} used by {where} ' \
               f'(frame #{location["frame_index"]}, {location["version"]})'
    exact = ', the frame line is a changed line' if location.get('on_changed_line') else ''
    return f'{location["hunk_id"]} changes {where}, the {location["role"]} (frame #{location["frame_index"]}) ' \
           f'of the {location["version"]} failure{exact}'


def relation(finding_id, hunks, locations, run_ids, value, evidence, limitation=LIMITATION):
    return {'schema_version': '1.0', 'finding_id': finding_id,
            'hunk_ids': sorted({l['hunk_id'] for l in locations}, key=lambda h: int(h[1:]) if h[1:].isdigit() else 0),
            'locations': locations, 'paired_run_ids': run_ids, 'relation': value,
            'evidence': evidence, 'limitation': limitation}


def failing_checks(evaluation):
    """Frozen set of failed oracle check names, or ``None`` when detail is unavailable.

    A status-only evaluation (e.g. an older report that stored only ``'fail'``) has
    no ``checks`` map and therefore cannot prove *which* condition failed; it
    returns ``None`` so a re-computed functional correlation stays ``unknown``
    instead of overclaiming (review item 1.2).
    """
    if not isinstance(evaluation, dict):
        return None
    checks = evaluation.get('checks')
    if not isinstance(checks, dict):
        return None
    return frozenset(name for name, ok in checks.items() if ok is False)


def functional_diagnostic_error(coverage, main, version):
    test_id = main['test_id']
    if coverage is None:
        return f'no coverage record for test {test_id} ({version})'
    if coverage.get('status') != 'ok':
        return f'coverage unavailable for test {test_id} ({version}): {coverage.get("reason")}'
    if (coverage.get('diagnostic_signal') is not None or coverage.get('diagnostic_timeout')
            or coverage.get('diagnostic_output_truncated') or coverage.get('diagnostic_runner_error')
            or coverage.get('diagnostic_resource_status') not in (None, 'ok')):
        return f'diagnostic run for test {test_id} ({version}) did not terminate cleanly'
    if not main.get('input_sha256') or coverage.get('input_sha256') != main['input_sha256']:
        return f'coverage input hash does not match the finding run for test {test_id} ({version})'

    diagnostic = coverage.get('diagnostic_oracle')
    diagnostic_fails = failing_checks(diagnostic)
    main_oracle = main.get('oracle')
    main_fails = failing_checks(main_oracle)
    if diagnostic_fails is None:
        return f'diagnostic run for test {test_id} ({version}) has no oracle check detail'
    if main_fails is None:
        return f'main {version} run for test {test_id} has no oracle check detail'
    if version == 'base':
        if (diagnostic.get('status') != 'pass' or main_oracle.get('status') != 'pass'
                or diagnostic_fails or main_fails or not main_oracle['checks']
                or diagnostic['checks'] != main_oracle['checks']):
            return f'diagnostic baseline for test {test_id} did not match the passing oracle checks'
        return None

    if diagnostic.get('status') != 'fail' or not diagnostic_fails:
        return f'diagnostic run for test {test_id} did not fail the oracle'
    if main_fails != diagnostic_fails:
        return (f'diagnostic and main run failed different oracle checks for test {test_id} '
                f'(main={sorted(main_fails)}, diagnostic={sorted(diagnostic_fails)})')
    for check in sorted(main_fails):
        field = f'{check}_sha256' if check in ('stdout', 'stderr') else check
        main_value = main.get(field)
        if main_value is None or main_value != coverage.get(f'diagnostic_{field}'):
            return f'observed {check} differs or is missing in the diagnostic comparison'
    return None


def functional_coverage_relation(finding, hunks, coverage_runs, base, candidate, run_ids):
    test_id = candidate.get('test_id')
    if (not test_id or base.get('test_id') != test_id or not candidate.get('input_sha256')
            or base.get('input_sha256') != candidate['input_sha256']):
        return relation(finding['id'], hunks, [], run_ids, 'unknown',
                        ['the paired runs do not establish the same test and input'])
    changed = sorted({f'{c["file"]}:{c["function"]}' for h in hunks for c in h['functions']})
    locations, evidence = [], []
    for version, side, main, role in (
            ('base', 'removed', base, 'covered-removed-line'),
            ('candidate', 'added', candidate, 'covered-changed-line')):
        if not any(hunk.get(side) for hunk in hunks):
            continue
        coverage = next((record for record in coverage_runs
                         if record.get('test_id') == test_id
                         and record.get('version', 'candidate') == version), None)
        error = functional_diagnostic_error(coverage, main, version)
        if error:
            evidence.append(error)
            continue
        hits = covered_changes(hunks, coverage.get('coverage') or {}, version)
        failed = set(coverage.get('gcov_failed_files') or [])
        bad_files = sorted({h['file'] for h in hits if h['file'] in failed})
        if bad_files:
            evidence.append(f'gcov extraction failed for the cited file(s): {", ".join(bad_files)}')
        for hit in hits:
            if hit['file'] in failed:
                continue
            locations.append({**hit, 'version': version, 'role': role, 'run_id': coverage['run_id']})
            execution = 'passing baseline' if version == 'base' else 'failing functional run'
            evidence.append(f'{hit["hunk_id"]} changes {", ".join(hit["functions"]) or "unmapped"} in {hit["file"]}; '
                            f'covered lines {hit["covered_lines"]} are executed by the {execution} '
                            f'(test {test_id}, diagnostic run {coverage["run_id"]})')
        if not hits:
            evidence.append(f'no {side} line is covered by the {version} diagnostic; it is not attributed')
        if coverage.get('ambiguous'):
            evidence.append(f'ambiguous coverage basenames were not attributed: {", ".join(coverage["ambiguous"])}')
    if not locations:
        evidence.insert(0, f'changed functions: {", ".join(changed) or "none mapped"}')
    return relation(finding['id'], hunks, locations, run_ids, 'confirmed' if locations else 'unknown', evidence,
                    'Functional correlation uses a separate diagnostic build. Executed removed lines are '
                    'observed on the passing baseline and executed added lines on the failing candidate. '
                    'Coverage links a change to the observed path without establishing root cause.')


def correlate(diff, findings, paired_runs):
    """One PatchRelation per finding: confirmed / candidate / unknown with the evidence used.

    `confirmed` is reserved for a direct data/control-flow link (the crashing
    frame line is itself a changed line). Mere presence — a changed function on
    the failing stack or a changed macro used by a stack function — is a
    `candidate` and never auto-confirms. A changed callee reachable only
    statically is reported as evidence but stays off the stack (unknown).
    """
    hunks = (diff or {}).get('hunks') or []
    graph = (diff or {}).get('source_map') or {}
    runs = {run['id']: run for run in paired_runs}
    relations = []
    for finding in findings:
        run_ids = [*finding.get('base_run_ids', []), *finding.get('candidate_run_ids', [])]
        base = runs.get((finding.get('base_run_ids') or [None])[0])
        candidate = runs.get((finding.get('candidate_run_ids') or [None])[0])
        status = finding.get('status')
        if not hunks:
            relations.append(relation(finding['id'], hunks, [], run_ids, 'unknown',
                                      ['the diff has no hunks'], 'Nothing to correlate.'))
            continue
        if not graph or any('functions' not in h for h in hunks):
            relations.append(relation(finding['id'], hunks, [], run_ids, 'unknown',
                                      ['the diff has no source map (report produced by an older version)']))
            continue
        if base is None or candidate is None:
            relations.append(relation(finding['id'], hunks, [], run_ids, 'unknown', ['paired runs are missing']))
            continue
        if status == 'Functional Regression':
            coverage = (diff or {}).get('coverage') or {}
            relations.append(functional_coverage_relation(finding, hunks, coverage.get('runs') or [],
                                                          base, candidate, run_ids))
            continue

        # Which version's stack explains the finding.
        version, run = ('candidate', candidate) if status == 'New Issue' else ('base', base)
        obs, path = failing_stacks(run)
        if not path:
            reason = 'fixture evidence has no stack' if (obs or {}).get('confirmation') == 'fixture' else \
                f'the {version} {run.get("build_type")} run has no symbolized in-program stack' + \
                (' (see the sanitized pair)' if run.get('build_type') == 'release' else '')
            relations.append(relation(finding['id'], hunks, [], run_ids, 'unknown', [reason]))
            continue
        locations = path_locations(version, path, hunks, graph)
        cand_obs, cand_path = failing_stacks(candidate) if status == 'Incomplete Fix' else (None, [])
        if cand_path:
            locations += [l for l in path_locations('candidate', cand_path, hunks, graph) if l not in locations]
        on_path = [l for l in locations if l['role'] in PATH_ROLES]
        siblings = sibling_locations(version, path, hunks, graph)
        evidence = [describe(l) for l in on_path + siblings]
        unmapped = [h['id'] for h in hunks if h.get('unmapped')]
        if unmapped:
            evidence.append(f'hunks outside any function (not mapped): {", ".join(unmapped)}')
        crash_site = next((f for role, _, f in path if role == 'crash-site'), None)
        site = f'{crash_site["project_file"]}:{crash_site["function"]}' if crash_site else 'unknown'

        # Evidence is graded, not boolean. The only static proof of a data/control-flow
        # link is the crashing frame line being itself a changed line; every other
        # overlap *on the failing stack* (a changed function on the stack, a changed
        # macro used by a stack function) is a *candidate* and never auto-confirms.
        # A changed callee that is only statically reachable (sibling) is reported as
        # evidence but stays off the stack, so it does not even make a candidate.
        confirmed = [l for l in on_path if l['role'] == 'crash-site' and l.get('on_changed_line')]
        candidates = [l for l in on_path if l not in confirmed]

        if status == 'Inconclusive':
            value = 'unknown'
            evidence.append('the finding itself is inconclusive')
        elif confirmed:
            value = 'confirmed'
            evidence.append({f'Fixed': f'the change is at the crash site {site}: the crashing frame line is '
                                      f'itself a changed line, tying the change to the prevented failure',
                             'Incomplete Fix': f'the change is at the crash site {site}: the crashing frame line '
                                               f'is itself a changed line and the same failure persists',
                             'New Issue': f'the change is at the crash site {site}: the crashing frame line is '
                                          f'itself a changed line on the candidate'}.get(
                                 status, f'the change is at the crash site {site}'))
        elif candidates:
            value = 'candidate'
            evidence.append('a changed function or macro appears on or near the failing path, but the '
                            'static evidence does not establish a data or control-flow link between the '
                            'specific change and the failure; the finding status is independent of this '
                            'candidate relation')
        elif status == 'Incomplete Fix' and not unmapped and stack_complete(obs) and \
                cand_path and stack_complete(cand_obs):
            # No changed function is on the failing stack and the stack is complete
            # down to main; absence from the stack still never *rejects* the relation.
            value = 'unknown'
            evidence.append(f'the failure at {site} persists on the candidate and no hunk changes a function on its '
                            f'stack (complete down to main); a changed function may still have run and returned '
                            f'earlier, so the relation cannot be rejected from the stack alone')
        else:
            value = 'unknown'
            evidence.append({'Fixed': f'the crash at {site} disappeared, but no changed function is on its stack; '
                                      f'the fix may act through code that returned before the crash',
                             'New Issue': f'no changed function is on the stack of the new failure at {site}'}
                            .get(status, f'no changed function is on the stack of the failure at {site}'))
        relations.append(relation(finding['id'], hunks, on_path + siblings, run_ids, value, evidence))

    # A release finding has no stack of its own; point to the sanitized pair of the same test.
    by_id = {r['finding_id']: r for r in relations}
    for finding in findings:
        if finding['id'].endswith('-release') and by_id[finding['id']]['relation'] == 'unknown':
            twin = by_id.get(finding['id'][:-len('release')] + 'sanitized')
            if twin and twin['relation'] != 'unknown':
                by_id[finding['id']]['evidence'].append(
                    f'sanitized pair {twin["finding_id"]} is {twin["relation"]}; this release relation stays '
                    f'unknown because it has no stack of its own')
    return relations
