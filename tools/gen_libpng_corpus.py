"""Generate libpng (pnginfo) test inputs and independent oracles.

Every PNG here is built byte by byte from the PNG specification, and every
expected result is computed from the specification and the documented libpng
behaviour (see oracles/libpng/SPEC.md) -- never by running pnginfo.

Target: the CVE-2015-8126 heap-buffer-overflow (and its incomplete fix
CVE-2015-8472) in libpng's png_set_PLTE / png_get_PLTE, which did not clamp the
palette size to the image bit depth. A palette PNG with a small bit depth
(1/2/4) can therefore carry up to 256 PLTE entries.

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


CASES = [
    ("valid-bit8", "valid", png(8, 256), b"OK 1 1 8 3 256\n", b"", 0, "Rendering"),
    ("valid-bit1", "valid", png(1, 2), b"OK 1 1 1 3 2\n", b"", 0, "Rendering"),
    ("boundary-bit4-max", "boundary", png(4, 16), b"OK 1 1 4 3 16\n", b"", 0, "Rendering"),
    ("invalid-no-plte", "invalid", png(1, 0, plte=False), b"", b"png error\n", 1, "Errors"),
    ("invalid-bad-depth", "invalid", png(16, 2), b"", b"png error\n", 1, "Errors"),
    ("poc-bit1-256pal", "original", png(1, 256), b"OK 1 1 1 3 2\n", b"", 0, "Security property"),
    ("poc-bit2-256pal", "original", png(2, 256), b"OK 1 1 2 3 4\n", b"", 0, "Security property"),
]


if __name__ == "__main__":
    for case_id, category, data, stdout, stderr, exit_code, section in CASES:
        (INPUTS / f"{case_id}.png").write_bytes(data)
        (ORACLES / f"{case_id}.json").write_text(json.dumps(oracle(section, exit_code, stdout, stderr), indent=2) + "\n")
        print(f"wrote {case_id}.png and {case_id}.json")
