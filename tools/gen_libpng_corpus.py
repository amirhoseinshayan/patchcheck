"""Generate libpng (pnginfo) test inputs and independent oracles.

Every PNG here is built byte by byte from the PNG specification, and every
expected result is computed from the specification and the documented libpng
behaviour (see oracles/libpng/SPEC.md) -- never by running pnginfo.

Target: CVE-2015-8126 and its incomplete fix CVE-2015-8472. libpng's
png_set_PLTE / png_get_PLTE did not clamp the palette size to the bit depth.
`pnginfo` reads a palette PNG and then re-encodes it through png_set_PLTE with a
256-entry palette; for a small bit depth (1/2/4) that palette is larger than the
correct maximum (1 << bit_depth) and must be rejected, but the vulnerable and
incompletely-fixed builds accept it and then overflow a correctly-sized buffer.

Run: python3 tools/gen_libpng_corpus.py
"""
import base64
import json
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "corpus" / "libpng" / "inputs"
ORACLES = ROOT / "oracles" / "libpng"
INPUTS.mkdir(parents=True, exist_ok=True)
ORACLES.mkdir(parents=True, exist_ok=True)


def chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def png(bit_depth, n_palette, width=1, height=1, plte=True):
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, bit_depth, 3, 0, 0, 0)  # color type 3 (palette)
    out = sig + chunk(b"IHDR", ihdr)
    if plte:
        plte_data = b"".join(struct.pack("BBB", (i * 3) & 0xFF, (i * 5) & 0xFF, (i * 7) & 0xFF) for i in range(n_palette))
        out += chunk(b"PLTE", plte_data)
    out += chunk(b"IDAT", zlib.compress(b"\x00\x00")) + chunk(b"IEND", b"")
    return out


def oracle(section, exit_code, stdout=b"", stderr=b""):
    return {
        "schema_version": "1.0",
        "provenance": {"source": f"oracles/libpng/SPEC.md#{section}", "independent": True},
        "exit_code": exit_code,
        "stdout": {"mode": "exact", "base64": base64.b64encode(stdout).decode()},
        "stderr": {"mode": "exact", "base64": base64.b64encode(stderr).decode()},
    }


# (id, category, input bytes, correct stdout, correct stderr, exit code, section)
CASES = [
    ("valid-bit8", "valid", png(8, 128), b"OK 1 1 8 3 256\n", b"", 0, "Rendering"),
    ("boundary-bit8-max", "boundary", png(8, 256), b"OK 1 1 8 3 256\n", b"", 0, "Rendering"),
    ("invalid-no-plte", "invalid", png(1, 0, plte=False), b"", b"png error\n", 1, "Errors"),
    ("invalid-bad-depth", "invalid", png(16, 2), b"", b"png error\n", 1, "Errors"),
    # Security PoCs: a small bit depth where the re-encoded 256-entry palette
    # exceeds 1 << bit_depth. The correct build rejects it (png error); the
    # vulnerable and incompletely-fixed builds accept it and overflow.
    ("poc-bit1-256pal", "original", png(1, 256), b"", b"png error\n", 1, "Security property"),
    ("poc-bit2-256pal", "original", png(2, 256), b"", b"png error\n", 1, "Security property"),
]


if __name__ == "__main__":
    for case_id, category, data, stdout, stderr, exit_code, section in CASES:
        (INPUTS / f"{case_id}.png").write_bytes(data)
        (ORACLES / f"{case_id}.json").write_text(json.dumps(oracle(section, exit_code, stdout, stderr), indent=2) + "\n")
        print(f"wrote {case_id}.png and {case_id}.json")
