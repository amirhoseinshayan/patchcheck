# Patchcheck — final delivery 1.0.9

- Archive version: 1.0.9 (= Python package version in both `pyproject.toml` files).
- Packaged: 2026-11-18

## Layout

- `src/`, `configs/`, `targets/`, `oracles/`, `corpus/`, `schemas/`, `tests/`, `ci/`,
  `environment/`, `tools/`, `vendor/`, `docs/` — tool, configuration, tests.
- `results/` — reference summaries (raw evidence intentionally absent).
- `evidence/scenarios/<name>/` — full self-contained reports.
- `evidence/reload/` — regression reload + bundle rebuild reports.
- `evidence/ci/` — `smoke-manifest.json` + logs.
- `evidence/bundles/` — a representative reproduction bundle.

## Historical local CI for 1.0.4

- The original `evidence/ci/smoke-manifest.json` records 26 of 26 steps and job exit 0.
- It records outcomes 0, 10 and 20 for both tlvparse and giflib. The historical
  `patch-unseen` step applied the known giflib patch via a Diff.
- The current smoke script calls that step `known-patch-via-diff` and includes a
  separate `patch-harmless-diff` step. Those names describe the current script.
- The archived 1.0.4 reports, logs and their supporting evidence retain their
  original contents.

## Historical local verification for 1.0.5

- The validator loaded all 18 historical reports and verified their schemas,
  references and evidence hashes. The schema accepts legacy minimization scope
  entries and requires all three new detail fields when any one appears.
- The delivered Linux x86_64 image ran the unit suite under amd64 emulation
  on an ARM host. The runner collected 160 tests, passed 158 and skipped 2
  that require generated fixture repositories.
  Both skipped CLI checks passed separately after fixture setup on the host.
- A new `bytecount-stdin` run and its harmless marker minimization both
  returned the expected exit 40. The fresh report passed schema and evidence
  validation. The registered corpus manifest, JSON scope and summary agreed.
- New evidence is under `evidence/verification-1.0.5/`. The `bytecount/`
  directory contains the captured report and its referenced evidence. The
  sibling `corpus/` directory contains the archived registration files.
  Absolute paths in the captured output identify the original test environment.
- Verification of the complete 1.0.5 smoke workflow on a hosted or native
  x86_64 runner remains open.

## Historical local verification for 1.0.6

- The included Linux x86_64 image ran 160 unit tests successfully under amd64
  emulation on an ARM host. Two additional CLI checks passed on the host after
  fixture setup.
- An independent harmless bytecount patch returned exit 20. Both build kinds
  reported a functional regression with a confirmed relation to the changed
  line. The captured gcov output and the diagnostic stdout and stderr hashes
  are in `evidence/verification-1.0.6/bytecount-evidence/`. This report records
  the coverage check with follow-up disabled to keep the verification bundle
  small. A separate normal CLI run also returned exit 20.
- The tlvparse and giflib functional subsets passed 16 of 16 and 12 of 12
  independent oracle comparisons across the four build cells. These subsets
  return exit 40 because they contain only functional inputs. See
  `evidence/verification-1.0.6/` for the reports and manifest of checks.
- All 19 reports from previous releases remain readable. Verification of the
  complete 1.0.6 smoke workflow on a hosted or native x86_64 runner is open.
- Target selection and the reference criteria are in `docs/teacher-proposal.md`.

## Local verification for 1.0.7

- The delivered Linux x86_64 image under amd64 emulation ran 163 unit tests
  successfully. Two additional CLI tests passed on the host after fixture setup.
- A harmless deletion-only Diff returned exit 20 with two confirmed locations
  citing the executed removed line in the passing baseline. A harmless
  replacement Diff returned exit 20 with both baseline and candidate witnesses.
  The coverage checks used the normal pipeline with follow-up disabled.
- The harmless marker fixture reduced an input and registered it in the
  regression corpus. The report, scope and archived manifest match.
- New reports and logs are under `evidence/verification-1.0.7/`. All 22
  previous reports still validate. The full hosted/native smoke run remains
  open, as does minimization coverage for findings present only in a candidate.

## Local verification for 1.0.8

- Closes the 1.0.7 minimization gap: `minimize` now also handles **candidate-only
  (New Issue)** findings, not just base-reproduced ones. `minimize.choose_direction`
  picks `base` when the signature reproduces on `base/sanitized` and `candidate`
  when it reproduces only on `candidate/sanitized` with a clean base.
- A candidate-only minimized input is registered with
  `regression = {signature, base_absence_required: true, candidate_reproduce_required: true}`
  and re-evaluated on the next run: the base must stay clean and the candidate must
  still reproduce the new error (a New Issue finding, exit 10).
- Verified end-to-end on a synthesized `tlvparse` new-issue target (an unchecked
  type-4 handler): run → New Issue (exit 10) → `minimize --test` (`direction=candidate`,
  `registered=true`) → reload (candidate-only regression loaded, `generated_regression`
  `status=pass` on both build kinds, New Issue still detected).
- Unit suite: 174 tests pass (2 skipped). `FinalReport.schema.json` `generated_regression`
  gained a `direction` discriminator and the candidate-only fields; the two schema
  copies and `tools/generate_schemas.py` are in sync.
- The full hosted/native smoke run remains open; target selection and reference
  criteria are in `docs/teacher-proposal.md` (pending teacher sign-off).

## Changes for 1.0.9 (third target: libpng)

- Added a third real target, **libpng** (`pnginfo`), covering CVE-2015-8126 and
  its incomplete fix CVE-2015-8472 (`png_set_PLTE` / `png_get_PLTE` did not clamp
  the palette size to the bit depth). `targets/libpng/` holds `base` (1.6.18),
  `correct`, `incomplete` and `regression`; `configs/libpng-file.json`,
  `corpus/libpng/`, `oracles/libpng/` and `tools/gen_libpng_corpus.py` were added.
  The environment image now installs `zlib1g-dev` (libpng links `-lz`/`-lm`).
- The three patch scenarios return the expected verdicts: `correct` → 0,
  `incomplete` → 10 (the observed bit-depth-1 PoC is blocked but a different
  bit-depth-2 input still overflows) and `regression` → 20 (a valid 8-bit palette
  is wrongly truncated). The release build detects the overflow through
  glibc-malloc-check and the sanitized build through AddressSanitizer, kept
  separate per §3.2.
- Tool fix: `analysis.LIBC_CHECKS` now recognises glibc's exact
  `malloc(): corrupted top size` (and the sibling `corrupted unsorted chunks`,
  `invalid size (unsorted)`, `unsorted/smallbin double linked list corrupted`)
  heap-corruption diagnostics as a confirmed `glibc-malloc-check` finding instead
  of an unclassified bare abort. A unit test covers the new pattern.
- Hosted CI is now green: GitHub Actions run
  https://github.com/amirhoseinshayan/patchcheck/actions/runs/44259284322 on
  commit `ee02909` completed with **success**, 31 of 31 smoke steps passed. The
  three libpng scenarios are recorded in the manifest with their exact codes
  (`correct` 0, `incomplete` 10, `regression` 20).

## Reproducing

```
python3 -m venv .venv && .venv/bin/python ci/bootstrap.py
python3 tools/setup_fixtures.py
docker build --platform linux/amd64 -t patchcheck-framework:1.0 -f environment/Dockerfile .
.venv/bin/python ci/smoke.py --out artifacts/ci
```

## Docker image and offline reconstruction

The exact toolchain image is delivered as a separate attachment (NOT inside this ZIP):

- file: `patchcheck-framework-1.0.tar`
- size: 483155456 bytes
- SHA-256: `80c63cfac3a7dfc12e7cbbf72c9efedb6c2b2ef2d9eec8afcdddf2b6b480cf83`
- internal Docker id: `sha256:dce79fafdcefc7e1f4d650b0503722d49c63009912b5957d89ec8c267dd4b92b` (tag `patchcheck-framework:1.0`)

Load it with `docker image load --input patchcheck-framework-1.0.tar`, then verify with
`docker image inspect sha256:dce79fafdcefc7e1f4d650b0503722d49c63009912b5957d89ec8c267dd4b92b`. After loading, `patchcheck reproduce` accepts the
exact id above. A fresh `docker build` from `environment/Dockerfile` produces a
DIFFERENT id and is not accepted as identical.
