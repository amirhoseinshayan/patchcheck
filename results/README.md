# Results — generated reports and reproduction evidence

Reference snapshots of every scenario's `summary.md` and `report.json`, refreshed
with the current (remediated) code via `ci/smoke.py --out artifacts/ci`. The
referenced raw evidence trees are **not** committed beside the JSON files (they are
large and reproducible); the full self-contained evidence is inside each run's
`artifacts/ci/<scenario>/` directory and in the reproduction bundle.

To regenerate a single scenario with complete evidence:

```bash
.venv/bin/patchcheck run configs/tlvparse-file.json --candidate correct --out <dir>
```

The `report.json` files below are schema-valid and carry the current verdicts
(0/10/20/40). Run `patchcheck report <dir>/report.json` only against a full run
directory (which contains the evidence), not against these stripped snapshots.

Regenerate reports
with `ci/smoke.py --out artifacts/ci`, or a single scenario with, e.g.,
`.venv/bin/patchcheck run configs/giflib-file.json --candidate correct --out <dir>`.

Each `run` now **automatically**: executes the full base/candidate × release/
sanitized matrix, replays every confirmed finding (security or functional
regression) three extra times per cell (§3.3), re-decides the verdict with that
replay stability, and writes an evidence bundle for confirmed findings. Functional-only automatic bundles include the toolchain image.

## Scenario reports

One folder per scenario with the human-readable `summary.md` and the schema-
validated `report.json`. The reports carry the replay evidence (`replays`,
`replay_stability`) and the bundle reference.

| Scenario | Target | Verdict | Replays |
|---|---|---|---|
| `tlvparse-correct` | own C program | 0 PASS | 3 |
| `tlvparse-incomplete` | own C program | 10 VULN_REMAINS | 3 |
| `tlvparse-regression` | own C program | 20 FUNC_REGRESSION | 5 |
| `giflib-correct` | giflib `gif2rgb`, CVE-2016-3977 | 0 PASS | 3 |
| `giflib-incomplete` | giflib `gif2rgb`, CVE-2016-3977 | 10 VULN_REMAINS | 3 |
| `giflib-regression` | giflib `gif2rgb`, CVE-2016-3977 | 20 FUNC_REGRESSION | 5 |
| `libpng-correct` | libpng `pnginfo`, CVE-2015-8126/8472 | 0 PASS | 2 |
| `libpng-incomplete` | libpng `pnginfo`, CVE-2015-8126/8472 | 10 VULN_REMAINS | 2 |
| `libpng-regression` | libpng `pnginfo`, CVE-2015-8126/8472 | 20 FUNC_REGRESSION | 3 |
| `bytecount` | harmless fixture (self-test) | 40 INCONCLUSIVE | 0 |
| `lineparse` | harmless fixture (self-test) | 40 INCONCLUSIVE | 0 |

The historical test lists include the previously generated regressions: the automatically minimized
regression tests are committed under `corpus/tlvparse/regressions/` and
`corpus/giflib/regressions/`, so a fresh run
produces the same test list. The raw per-run evidence trees are not committed
(large, reproducible); the full self-contained evidence is inside the bundle.

## Crash inputs (`crash-inputs/`)

| File | Bytes | What |
|---|---|---|
| `tlvparse-poc-long-blob.bin` | 159 | heap-buffer-overflow PoC for tlvparse |
| `tlvparse-minimized.bin` | 72 | ddmin-reduced regression input (committed as a corpus test) |
| `giflib-poc-bg-oob.gif` | 44 | CVE-2016-3977 PoC; ddmin finds no smaller input (GIF is rigid), registered as a corpus test unchanged |
| `libpng-poc-bit1-256pal.png` | 847 | CVE-2015-8126 PoC (1-bit palette PNG with 256 PLTE entries) |

## Reproduction bundle

`sample-bundle-vuln-remains.tar.gz` is a light bundle (no Docker image) for the
`tlvparse-incomplete` scenario — a **verdict 10** case where the vulnerability
remains, which is the kind the reviewer flagged as missing. Every `run` writes
its own such bundle; only this one representative bundle is committed (bundles are
a few MB each). Rebuild and re-verify offline with:

```
.venv/bin/patchcheck reproduce results/sample-bundle-vuln-remains.tar.gz --out <dir>
```

(the frozen `patchcheck-framework:1.0` image must be present locally).

## Note on giflib replay

giflib's bug is an out-of-bounds *read*: its hardened release build does not
crash but prints the bytes it read, so that build's output is nondeterministic.
The replay-stability check treats a base build that never shows a confirmed crash
as not carrying crash evidence, so that nondeterminism is ignored and giflib's
findings replay stably and are verdicted correctly. The same rule lets giflib's
PoC pass the stable threefold replay required before registration, so both real
targets have a committed generated regression: tlvparse (159 → 72 bytes) and
giflib (44 bytes, no reduction possible). See `docs/architecture.md`.
