"""Static source map of C/C++ trees for patch correlation.

The map is computed once from the exact snapshot trees and stored with the diff,
so `analysis.correlate` stays a pure function of the report. It records:
  * which function (by span) each changed line of each hunk belongs to,
  * macros (#define) a hunk changes,
  * static callers of every changed function and users of every changed macro.

This is a lightweight lexical scanner, not a compiler front end. Comments,
strings and preprocessor lines are blanked first; function definitions are
found as `name(...) {` at file/namespace/class level. Anything it cannot map
(lines outside a function that are not #define) is reported as unmapped, which
keeps correlation at `unknown` rather than guessing.
"""
import re
from pathlib import Path

CODE_SUFFIXES = {'.c', '.h', '.cc', '.cpp', '.cxx', '.c++', '.hpp', '.hh', '.hxx', '.inl', '.ipp'}
MAX_FILE_BYTES = 2_000_000
NOT_FUNCTIONS = {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'catch', 'do', 'else', 'case',
                 'defined', 'alignof', 'decltype', 'static_assert', 'typeof', '_Generic', 'alignas',
                 '__attribute__', '__declspec', '__asm__', 'asm'}
CANDIDATE = re.compile(r'(~?[A-Za-z_]\w*(?:\s*::\s*~?[A-Za-z_]\w*)*)\s*\($')
ACCESS_LABEL = re.compile(r'\s*(?:(?:public|private|protected)\s*:(?!:)\s*)+')
CONTAINER = re.compile(r'^\s*(?:template\s*<[^{}]*>\s*)?(?:namespace|class|struct|union)\b[^()]*$'
                       r'|^\s*extern\s*"\s*"\s*$|^\s*namespace\s*$', re.S)
DEFINE = re.compile(r'^\s*#\s*define\s+([A-Za-z_]\w*)')


def qualified_name(function):
    """Drop frame arguments while keeping C++ qualification."""
    if not function:
        return None
    depth, cut = 0, len(function)
    for index, char in enumerate(function):   # drop the parameter list (first top-level paren)
        if char == '<':
            depth += 1
        elif char == '>':
            depth -= 1
        elif char == '(' and depth == 0 and index > 0 and not function.startswith('operator', max(0, index - 8)):
            cut = index
            break
    name = function[:cut].strip()
    name = re.sub(r'<[^<>]*>', '', name)        # template arguments
    return name.split()[-1] if name else None


def short_name(function):
    name = qualified_name(function)
    return name.split('::')[-1] if name else None


def blank(text):
    """Replace comments, string/char literals and preprocessor lines with spaces (newlines kept)."""
    return _blank_literals(text, preprocessor=True)


def blank_comments_and_strings(text):
    """Replace only comments and string/char literals with spaces (newlines kept).

    Unlike `blank`, preprocessor lines are kept, so a macro mentioned only in a
    comment or string is NOT detected as a use, while `#if defined(NAME)` / `#ifdef`
    uses still are.
    """
    return _blank_literals(text, preprocessor=False)


def _blank_literals(text, preprocessor):
    out, i, n = list(text), 0, len(text)
    line_start = True
    while i < n:
        c = text[i]
        if line_start and c in ' \t':
            i += 1
            continue
        if preprocessor and line_start and c == '#':       # preprocessor line incl. continuations
            while i < n and text[i] != '\n':
                if text[i] == '\\' and i + 1 < n and text[i + 1] == '\n':
                    out[i] = ' '
                    i += 2
                    continue
                out[i] = ' '
                i += 1
            continue
        line_start = c == '\n'
        if text.startswith('//', i):
            while i < n and text[i] != '\n':
                out[i] = ' '
                i += 1
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            end = n if end < 0 else end + 2
            for j in range(i, end):
                if text[j] != '\n':
                    out[j] = ' '
            i = end
        elif c in '"\'':
            j = i + 1
            while j < n and text[j] != c and text[j] != '\n':
                j += 2 if text[j] == '\\' else 1
            for k in range(i + 1, min(j, n)):
                if text[k] != '\n':
                    out[k] = ' '
            i = j + 1
        else:
            i += 1
    return ''.join(out)


def function_name(header):
    """Name of the function a `{` opens, or None if the header is not a function definition."""
    depth = 0
    for index, char in enumerate(header):
        if char == '(':
            if depth == 0:
                match = CANDIDATE.search(header[:index + 1])
                if match:
                    name = re.sub(r'\s+', '', match[1])
                    if name.split('::')[-1] not in NOT_FUNCTIONS:
                        before = header[:match.start()]
                        return None if '=' in before.replace('==', '') else name
            depth += 1
        elif char == ')':
            depth -= 1
    return None


def function_spans(text):
    """[{name, short, start, end}] for every function definition (1-based inclusive lines)."""
    code = blank(text)
    spans, stack = [], []           # stack entries: 'container' | 'function' | 'other'
    header_start = 0
    line_of = lambda pos: code.count('\n', 0, pos) + 1
    function_open = None
    scopes = []
    for pos, char in enumerate(code):
        if char == '{':
            inside_function = 'function' in stack or 'other' in stack
            if inside_function:
                stack.append('block')
                scopes.append('')
            else:
                header = code[header_start:pos]
                name = function_name(header)
                if name:
                    stack.append('function')
                    label = ACCESS_LABEL.match(header)
                    offset = label.end() if label else len(header) - len(header.lstrip())
                    scope = '::'.join(part for part in scopes if part)
                    qualified = f'{scope}::{name}' if scope else name
                    function_open = (qualified, line_of(header_start + offset))
                    scopes.append('')
                elif CONTAINER.match(header):
                    stack.append('container')
                    container = re.search(r'\b(?:namespace|class|struct|union)\s+([\w:]+)', header)
                    scopes.append(container[1] if container else '')
                else:
                    stack.append('other')
                    scopes.append('')
            header_start = pos + 1
        elif char == '}':
            kind = stack.pop() if stack else 'container'
            if scopes:
                scopes.pop()
            if kind == 'function' and function_open:
                name, start = function_open
                spans.append({'name': name, 'short': name.split('::')[-1], 'start': start, 'end': line_of(pos)})
                function_open = None
            header_start = pos + 1
        elif char == ';' and not ('function' in stack or 'other' in stack):
            header_start = pos + 1
    return spans


def enclosing(spans, line):
    return next((s for s in spans if s['start'] <= line <= s['end']), None)


def code_files(tree):
    tree = Path(tree)
    for path in sorted(tree.rglob('*')):
        if (path.is_file() and not path.is_symlink() and path.suffix.lower() in CODE_SUFFIXES
                and '.git' not in path.parts and path.stat().st_size <= MAX_FILE_BYTES):
            yield path.relative_to(tree).as_posix(), path.read_text(errors='replace')


def references(tree, functions, macros):
    """Static callers of `functions` and users of `macros` across every code file of `tree`."""
    callers = {name: [] for name in sorted(functions)}
    users = {name: [] for name in sorted(macros)}
    if not callers and not users:
        return callers, users
    call = re.compile(r'\b(' + '|'.join(map(re.escape, callers)) + r')\s*\(') if callers else None
    use = re.compile(r'\b(' + '|'.join(map(re.escape, users)) + r')\b') if users else None
    for file, text in code_files(tree):
        code_lines = blank(text).splitlines()
        literal_lines = blank_comments_and_strings(text).splitlines()
        for span in function_spans(text):
            body_code = '\n'.join(code_lines[span['start'] - 1:span['end']])
            # Macro uses are detected on comments/strings-blanked text so a macro
            # name inside a comment is never counted; preprocessor lines are kept.
            body_literal = '\n'.join(literal_lines[span['start'] - 1:span['end']])
            where = {'file': file, 'function': span['name']}
            for name in sorted(set(call.findall(body_code))) if call else ():
                calls = len(re.findall(r'\b' + re.escape(name) + r'\s*\(', body_code))
                if name != span['short'] or calls > 1:   # the header itself is not a call
                    callers[name].append(where)
            for name in sorted(set(use.findall(body_literal))) if use else ():
                users[name].append(where)
    return callers, users


def annotate(hunks, base_tree, candidate_tree):
    """Add `functions`, `unmapped_lines` and `defines` to each hunk; return the reference graph."""
    trees = {'base': Path(base_tree), 'candidate': Path(candidate_tree)}
    side = {'base': 'removed', 'candidate': 'added'}
    spans_cache = {}

    def spans(version, file):
        key = (version, file)
        if key not in spans_cache:
            path = trees[version] / file if file else None
            ok = (path is not None and path.is_file() and path.suffix.lower() in CODE_SUFFIXES
                  and path.stat().st_size <= MAX_FILE_BYTES)
            spans_cache[key] = function_spans(path.read_text(errors='replace')) if ok else None
        return spans_cache[key]

    changed = {'base': set(), 'candidate': set()}
    macros = set()
    for hunk in hunks:
        hunk['functions'], hunk['unmapped_lines'] = [], {'base': [], 'candidate': []}
        for version in ('base', 'candidate'):
            file = hunk.get('old_file' if version == 'base' else 'file')
            lines = hunk.get(side[version], [])
            file_spans = spans(version, file) or []
            anchors = [span for span in file_spans
                       if any(span['start'] <= line <= span['end'] for line in lines)]
            for line in lines:
                span = enclosing(file_spans or [], line)
                if span is None:
                    hunk['unmapped_lines'][version].append(line)
                    continue
            for span in anchors:
                entry = {'version': version, 'file': file, 'function': span['name'], 'short': span['short'],
                         'start': span['start'], 'end': span['end']}
                hunk['functions'].append(entry)
                changed[version].add(span['short'])
        # An insertion/deletion can lie inside a function present on both sides.
        # Correlate its counterpart only when its full name is unique on both sides
        # and the paired diff range intersects it.
        for entry in list(hunk['functions']):
            version = 'candidate' if entry['version'] == 'base' else 'base'
            file = hunk.get('old_file' if version == 'base' else 'file')
            target = [span for span in spans(version, file) or [] if span['name'] == entry['function']]
            source = [span for span in spans(entry['version'], entry['file']) or []
                      if span['name'] == entry['function']]
            if len(target) != 1 or len(source) != 1:
                continue
            span = target[0]
            diff_range = hunk['before' if version == 'base' else 'after']
            first = diff_range['start']
            if first > span['end'] or first + max(1, diff_range['count']) - 1 < span['start']:
                continue
            counterpart = {**entry, 'version': version, 'file': file, 'start': span['start'], 'end': span['end']}
            if counterpart not in hunk['functions']:
                hunk['functions'].append(counterpart)
        macros.update(hunk.get('defines', []))
        # Changed #define lines are mapped through the functions that use the macro.
        for version in ('base', 'candidate'):
            hunk['unmapped_lines'][version] = [line for line in hunk['unmapped_lines'][version]
                                               if line not in hunk.get('define_lines', {}).get(version, [])]
        hunk['unmapped'] = bool(hunk['unmapped_lines']['base'] or hunk['unmapped_lines']['candidate'])
    graph = {}
    for version in ('base', 'candidate'):
        callers, users = references(trees[version], changed['base'] | changed['candidate'], macros)
        graph[version] = {'callers': callers, 'macro_users': users}
    return graph
