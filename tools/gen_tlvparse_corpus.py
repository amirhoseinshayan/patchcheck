"""Generate tlvparse test inputs and independent oracles from oracles/tlvparse/SPEC.md.

Every expected result below is written by hand from the specification; no
version of the program is executed to produce it.
Run: python3 tools/gen_tlvparse_corpus.py
"""
import base64
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAGIC = b'TLV1'
# The vulnerability the patches address: an out-of-bounds write in copy_value().
TARGET_SIGNATURE = {'error_type': 'heap-buffer-overflow', 'location': 'tlvparse.c:copy_value', 'key': 'WRITE'}


def rec(kind, value):
    return bytes([kind, len(value)]) + value


def name(text):
    return rec(1, text)


def number(n):
    return rec(2, struct.pack('<i', n))


def blob(data):
    return rec(3, data)


def ok(*lines):
    return 0, ''.join(line + '\n' for line in lines), ''


def err(message):
    return 2, '', f'error: {message}\n'


# (id, category, input bytes, (exit code, stdout, stderr), spec section)
CASES = [
    ('valid-basic', 'valid', MAGIC + name(b'alice') + number(42) + blob(b'abc'),
     ok('name: alice', 'number: 42', 'blob: 3 bytes, sum=294', 'records: 3'), 'Input format'),
    ('valid-empty', 'valid', MAGIC, ok('records: 0'), 'Input format'),
    ('valid-negative', 'valid', MAGIC + number(-7) + name(b''), ok('number: -7', 'name: ', 'records: 2'), 'Input format'),
    ('boundary-name32', 'boundary', MAGIC + name(b'N' * 32), ok('name: ' + 'N' * 32, 'records: 1'), 'Input format'),
    ('boundary-blob32', 'boundary', MAGIC + blob(b'\x01' * 32), ok('blob: 32 bytes, sum=32', 'records: 1'), 'Input format'),
    ('boundary-16records', 'boundary', MAGIC + b''.join(number(i) for i in range(1, 17)),
     ok(*[f'number: {i}' for i in range(1, 17)], 'records: 16'), 'Input format'),
    ('invalid-magic', 'invalid', b'XLV1' + name(b'a'), err('bad magic'), 'Errors'),
    ('invalid-truncated', 'invalid', MAGIC + bytes([1, 10]) + b'abc', err('truncated record'), 'Errors'),
    ('invalid-type', 'invalid', MAGIC + rec(9, b'x'), err('unknown record type'), 'Errors'),
    ('invalid-numlen', 'invalid', MAGIC + rec(2, b'abc'), err('bad number length'), 'Errors'),
    ('invalid-17records', 'invalid', MAGIC + b''.join(number(i) for i in range(17)), err('too many records'), 'Errors'),
    # Security inputs: original proof of concept (long name) and a variant (long blob).
    ('poc-long-name', 'original', MAGIC + name(b'A' * 200), err('value too long'), 'Security property'),
    # Variant shaped like a fuzzer finding: valid records first, junk after the faulty record.
    ('poc-long-blob', 'original', MAGIC + name(b'alice') + number(42) + blob(b'B' * 100) + bytes(range(40)),
     err('value too long'), 'Security property'),
    # New Issue witness: a *valid* 16-byte blob. On the base it decodes cleanly; on
    # the new-issue branch a fixed 8-byte heap buffer in load_blob overflows.
    ('poc-blob-new', 'original', MAGIC + blob(b'\x01' * 16),
     ok('blob: 16 bytes, sum=16', 'records: 1'), 'Security property'),
]


def b64(text):
    return base64.b64encode(text.encode()).decode()


def generate():
    inputs = ROOT / 'corpus/tlvparse/inputs'
    oracles = ROOT / 'oracles/tlvparse'
    inputs.mkdir(parents=True, exist_ok=True)
    for case_id, _category, data, (code, stdout, stderr), section in CASES:
        (inputs / f'{case_id}.bin').write_bytes(data)
        oracle = {'schema_version': '1.0',
                  'provenance': {'source': f'oracles/tlvparse/SPEC.md#{section}', 'independent': True},
                  'exit_code': code,
                  'stdout': {'mode': 'exact', 'base64': b64(stdout)},
                  'stderr': {'mode': 'exact', 'base64': b64(stderr)}}
        (oracles / f'{case_id}.json').write_text(json.dumps(oracle, indent=2) + '\n')
    print(f'{len(CASES)} tlvparse cases written')


def config_tests():
    """Test list for configs/tlvparse-file.json (paths relative to configs/).

    Security inputs (category 'original') declare the target error signature.
    """
    return [{'id': case_id, 'category': category, 'input': f'../corpus/tlvparse/inputs/{case_id}.bin',
             'oracle': f'../oracles/tlvparse/{case_id}.json',
             'signature': TARGET_SIGNATURE if category == 'original' else None}
            for case_id, category, *_ in CASES]


if __name__ == '__main__':
    generate()
