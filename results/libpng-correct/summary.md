# Patchcheck: libpng

**Verdict: 0 PASS**

Versions: base `74b41dbf3b` → candidate `6e2695664f`
Builds: 4; tests: 6; executions: 48.

| Axis | Result |
|---|---|
| Security | fixed (target reproduced on base: yes) |
| Functional | preserved |
| Analysis complete | yes |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Fixed | heap-buffer-overflow | asan | pnginfo.c:25 in copy_palette | confirmed | stable | finding-security-poc-bit1-256pal-sanitized |
| Fixed | heap-buffer-overflow | asan | pnginfo.c:25 in copy_palette | confirmed | stable | finding-security-poc-bit2-256pal-sanitized |

## Patch correlation

Confirmed relationships cite a relevant stack frame or a covered changed line in the matching version. Unknown relationships lack sufficient evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
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
| valid-bit8 | release | pass | pass | preserved |
| valid-bit8 | sanitized | pass | pass | preserved |
| boundary-bit8-max | release | pass | pass | preserved |
| boundary-bit8-max | sanitized | pass | pass | preserved |
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
