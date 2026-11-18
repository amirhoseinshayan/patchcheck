# Patchcheck: libpng

**Verdict: 20 FUNC_REGRESSION**

Versions: base `74b41dbf3b` → candidate `d596eaed41`
Builds: 4; tests: 6; executions: 72.

| Axis | Result |
|---|---|
| Security | fixed (target reproduced on base: yes) |
| Functional | regression |
| Analysis complete | yes |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-valid-bit8-release |
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-valid-bit8-sanitized |
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-boundary-bit8-max-release |
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-boundary-bit8-max-sanitized |
| Fixed | heap-buffer-overflow | asan | pnginfo.c:25 in copy_palette | confirmed | stable | finding-security-poc-bit1-256pal-sanitized |
| Fixed | heap-buffer-overflow | asan | pnginfo.c:25 in copy_palette | confirmed | stable | finding-security-poc-bit2-256pal-sanitized |

## Patch correlation

Confirmed relationships cite a relevant stack frame or a covered changed line in the matching version. Unknown relationships lack sufficient evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-functional-valid-bit8-release | Functional Regression | **confirmed** | h84, h85, h90, h93 | h85 changes png_handle_PLTE in pngrutil.c; covered lines [962] are executed by the passing baseline (test valid-bit8, diagnostic run coverage-valid-bit8-base-6df62265dc1b); h90 changes png_read_IDAT_data in pngrutil.c; covered lines [4022] are executed by the passing baseline (test valid-bit8, diagnostic run coverage-valid-bit8-base-6df62265dc1b); h93 changes png_set_PLTE in pngset.c; covered lines [521] are executed by the passing baseline (test valid-bit8, diagnostic run coverage-valid-bit8-base-6df62265dc1b); h84 changes png_handle_PLTE in pngrutil.c; covered lines [972, 973, 977] are executed by the failing functional run (test valid-bit8, diagnostic run coverage-valid-bit8-candidate-42ba9e2fa7f6); h85 changes png_handle_PLTE in pngrutil.c; covered lines [1012] are executed by the failing functional run (test valid-bit8, diagnostic run coverage-valid-bit8-candidate-42ba9e2fa7f6); h90 changes png_read_IDAT_data in pngrutil.c; covered lines [4073] are executed by the failing functional run (test valid-bit8, diagnostic run coverage-valid-bit8-candidate-42ba9e2fa7f6); h93 changes png_set_PLTE in pngset.c; covered lines [523, 528, 529, 531] are executed by the failing functional run (test valid-bit8, diagnostic run coverage-valid-bit8-candidate-42ba9e2fa7f6) |
| finding-functional-valid-bit8-sanitized | Functional Regression | **confirmed** | h84, h85, h90, h93 | h85 changes png_handle_PLTE in pngrutil.c; covered lines [962] are executed by the passing baseline (test valid-bit8, diagnostic run coverage-valid-bit8-base-6df62265dc1b); h90 changes png_read_IDAT_data in pngrutil.c; covered lines [4022] are executed by the passing baseline (test valid-bit8, diagnostic run coverage-valid-bit8-base-6df62265dc1b); h93 changes png_set_PLTE in pngset.c; covered lines [521] are executed by the passing baseline (test valid-bit8, diagnostic run coverage-valid-bit8-base-6df62265dc1b); h84 changes png_handle_PLTE in pngrutil.c; covered lines [972, 973, 977] are executed by the failing functional run (test valid-bit8, diagnostic run coverage-valid-bit8-candidate-42ba9e2fa7f6); h85 changes png_handle_PLTE in pngrutil.c; covered lines [1012] are executed by the failing functional run (test valid-bit8, diagnostic run coverage-valid-bit8-candidate-42ba9e2fa7f6); h90 changes png_read_IDAT_data in pngrutil.c; covered lines [4073] are executed by the failing functional run (test valid-bit8, diagnostic run coverage-valid-bit8-candidate-42ba9e2fa7f6); h93 changes png_set_PLTE in pngset.c; covered lines [523, 528, 529, 531] are executed by the failing functional run (test valid-bit8, diagnostic run coverage-valid-bit8-candidate-42ba9e2fa7f6) |
| finding-functional-boundary-bit8-max-release | Functional Regression | **confirmed** | h84, h85, h90, h93 | h85 changes png_handle_PLTE in pngrutil.c; covered lines [962] are executed by the passing baseline (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-base-da64ded22a5d); h90 changes png_read_IDAT_data in pngrutil.c; covered lines [4022] are executed by the passing baseline (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-base-da64ded22a5d); h93 changes png_set_PLTE in pngset.c; covered lines [521] are executed by the passing baseline (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-base-da64ded22a5d); h84 changes png_handle_PLTE in pngrutil.c; covered lines [972, 973, 977] are executed by the failing functional run (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-candidate-815105d123cc); h85 changes png_handle_PLTE in pngrutil.c; covered lines [1012] are executed by the failing functional run (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-candidate-815105d123cc); h93 changes png_set_PLTE in pngset.c; covered lines [523, 528, 529, 531] are executed by the failing functional run (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-candidate-815105d123cc) |
| finding-functional-boundary-bit8-max-sanitized | Functional Regression | **confirmed** | h84, h85, h90, h93 | h85 changes png_handle_PLTE in pngrutil.c; covered lines [962] are executed by the passing baseline (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-base-da64ded22a5d); h90 changes png_read_IDAT_data in pngrutil.c; covered lines [4022] are executed by the passing baseline (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-base-da64ded22a5d); h93 changes png_set_PLTE in pngset.c; covered lines [521] are executed by the passing baseline (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-base-da64ded22a5d); h84 changes png_handle_PLTE in pngrutil.c; covered lines [972, 973, 977] are executed by the failing functional run (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-candidate-815105d123cc); h85 changes png_handle_PLTE in pngrutil.c; covered lines [1012] are executed by the failing functional run (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-candidate-815105d123cc); h93 changes png_set_PLTE in pngset.c; covered lines [523, 528, 529, 531] are executed by the failing functional run (test boundary-bit8-max, diagnostic run coverage-boundary-bit8-max-candidate-815105d123cc) |
| finding-security-poc-bit1-256pal-sanitized | Fixed | **confirmed** | h24, h93 | h24 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, base); h93 changes pngset.c:png_set_PLTE, called from main on the stack but not itself on the failing stack; hunks outside any function (not mapped): h2, h24, h29, h30, h31, h34, h35, h36, h39, h42, h43, h44, h45, h46, h58, h80, h97; the same input crashes base at pnginfo.c:copy_palette and not the candidate |
| finding-security-poc-bit2-256pal-sanitized | Fixed | **confirmed** | h24, h93 | h24 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, base); h93 changes pngset.c:png_set_PLTE, called from main on the stack but not itself on the failing stack; hunks outside any function (not mapped): h2, h24, h29, h30, h31, h34, h35, h36, h39, h42, h43, h44, h45, h46, h58, h80, h97; the same input crashes base at pnginfo.c:copy_palette and not the candidate |

## Binary hardening (release builds)

| Protection | Base | Candidate | Change |
|---|---|---|---|
| fortify_source | present | present | same |
| nx | enabled | enabled | same |
| pie | enabled | enabled | same |
| relro | full | full | same |
| stack_canary | present | present | same |

## Minimization coverage

Status: out-of-scope = not minimizable; supported = minimizable but not run; reduced / no-reduction / unstable / failed = outcome of an attempted run; registered = reduced-or-unchanged input written to the regression corpus; unrecorded = an older report did not record an outcome in this table.

| Finding | Status | Covered | Registered | Minimized test | Reason |
|---|---|---|---|---|---|
| finding-functional-valid-bit8-release | out-of-scope | no | no | - | functional regression has no crash signature to minimize |
| finding-functional-valid-bit8-sanitized | out-of-scope | no | no | - | functional regression has no crash signature to minimize |
| finding-functional-boundary-bit8-max-release | out-of-scope | no | no | - | functional regression has no crash signature to minimize |
| finding-functional-boundary-bit8-max-sanitized | out-of-scope | no | no | - | functional regression has no crash signature to minimize |
| finding-security-poc-bit1-256pal-sanitized | supported | yes | no | - | test has a matchable signature reproduced on the sanitized base |
| finding-security-poc-bit2-256pal-sanitized | supported | yes | no | - | test has a matchable signature reproduced on the sanitized base |

## Why the analysis is not complete

- (complete)

## Technical errors

- none

## Known limitations

- Patch correlation uses static stacks and a lexical source map; code that returned before a crash is not on its stack, and release builds have no stack.
- Hardening uses readelf indicators; missing canary/FORTIFY symbols are not proof that the protection is off.

## Functional comparisons

| Test | Build | Base oracle | Candidate oracle | Comparison |
|---|---|---|---|---|
| valid-bit8 | release | pass | fail | regression |
| valid-bit8 | sanitized | pass | fail | regression |
| boundary-bit8-max | release | pass | fail | regression |
| boundary-bit8-max | sanitized | pass | fail | regression |
| invalid-no-plte | release | pass | pass | preserved |
| invalid-no-plte | sanitized | pass | pass | preserved |
| invalid-bad-depth | release | pass | pass | preserved |
| invalid-bad-depth | sanitized | pass | pass | preserved |
| poc-bit1-256pal | release | fail | pass | baseline_fail |
| poc-bit1-256pal | sanitized | fail | pass | baseline_fail |
| poc-bit2-256pal | release | fail | pass | baseline_fail |
| poc-bit2-256pal | sanitized | fail | pass | baseline_fail |

## Crash classification

| Test | Version | Build | Error type | Detection | Termination | Access | Location | Evidence |
|---|---|---|---|---|---|---|---|---|
| poc-bit1-256pal | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 768 | pnginfo.c:25 in copy_palette | confirmed |
| poc-bit2-256pal | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 768 | pnginfo.c:25 in copy_palette | confirmed |
