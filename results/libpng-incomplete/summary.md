# Patchcheck: libpng

**Verdict: 10 VULN_REMAINS / NEW_ISSUE**

Versions: base `74b41dbf3b` → candidate `cd88a8fc3c`
Builds: 4; tests: 6; executions: 48.

| Axis | Result |
|---|---|
| Security | issue (target reproduced on base: yes) |
| Functional | unknown |
| Analysis complete | no |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Incomplete Fix | heap-buffer-overflow | asan | pnginfo.c:25 in copy_palette | confirmed | stable | finding-security-poc-bit1-256pal-sanitized |
| Incomplete Fix | heap-buffer-overflow | asan | pnginfo.c:25 in copy_palette | confirmed | stable | finding-security-poc-bit2-256pal-sanitized |

## Patch correlation

Confirmed relationships cite a relevant stack frame or a covered changed line in the matching version. Unknown relationships lack sufficient evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-security-poc-bit1-256pal-sanitized | Incomplete Fix | **confirmed** | h23, h79 | h23 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, base); h23 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, candidate); h79 changes pngset.c:png_set_PLTE, called from main on the stack but not itself on the failing stack; hunks outside any function (not mapped): h2, h23, h28, h29, h30, h33, h34, h35, h38, h41, h42, h43, h44, h45; the patch changes the failing path but the same failure at pnginfo.c:copy_palette persists on the candidate |
| finding-security-poc-bit2-256pal-sanitized | Incomplete Fix | **confirmed** | h23, h79 | h23 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, base); h23 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, candidate); h79 changes pngset.c:png_set_PLTE, called from main on the stack but not itself on the failing stack; hunks outside any function (not mapped): h2, h23, h28, h29, h30, h33, h34, h35, h38, h41, h42, h43, h44, h45; the patch changes the failing path but the same failure at pnginfo.c:copy_palette persists on the candidate |

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

- security-input-oracle: poc-bit1-256pal (release) candidate=fail
- security-input-oracle: poc-bit1-256pal (sanitized) candidate=fail
- security-input-oracle: poc-bit2-256pal (release) candidate=fail
- security-input-oracle: poc-bit2-256pal (sanitized) candidate=fail

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
| poc-bit1-256pal | release | fail | fail | both_fail |
| poc-bit1-256pal | sanitized | fail | fail | both_fail |
| poc-bit2-256pal | release | fail | fail | both_fail |
| poc-bit2-256pal | sanitized | fail | fail | both_fail |

## Crash classification

| Test | Version | Build | Error type | Detection | Termination | Access | Location | Evidence |
|---|---|---|---|---|---|---|---|---|
| poc-bit1-256pal | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 768 | pnginfo.c:25 in copy_palette | confirmed |
| poc-bit1-256pal | candidate | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 768 | pnginfo.c:25 in copy_palette | confirmed |
| poc-bit2-256pal | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 768 | pnginfo.c:25 in copy_palette | confirmed |
| poc-bit2-256pal | candidate | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 768 | pnginfo.c:25 in copy_palette | confirmed |
