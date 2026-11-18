# Patchcheck: libpng

**Verdict: 0 PASS**

Versions: base `d064d326ba` → candidate `1d538c09c5`
Builds: 4; tests: 7; executions: 52.

| Axis | Result |
|---|---|
| Security | fixed (target reproduced on base: yes) |
| Functional | preserved |
| Analysis complete | yes |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Fixed | heap-corruption | glibc-malloc-check | - | confirmed | stable | finding-security-poc-bit1-256pal-release |
| Fixed | heap-buffer-overflow | asan | pnginfo.c:29 in copy_palette | confirmed | stable | finding-security-poc-bit1-256pal-sanitized |
| Fixed | heap-corruption | glibc-malloc-check | - | confirmed | stable | finding-security-poc-bit2-256pal-release |
| Fixed | heap-buffer-overflow | asan | pnginfo.c:29 in copy_palette | confirmed | stable | finding-security-poc-bit2-256pal-sanitized |

## Patch correlation

Confirmed relationships cite a relevant stack frame or a covered changed line in the matching version. Unknown relationships lack sufficient evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-security-poc-bit1-256pal-release | Fixed | **unknown** | - | the base release run has no symbolized in-program stack (see the sanitized pair) |
| finding-security-poc-bit1-256pal-sanitized | Fixed | **unknown** | - | the crash at pnginfo.c:copy_palette disappeared, but no changed function is on its stack; the fix may act through code that returned before the crash |
| finding-security-poc-bit2-256pal-release | Fixed | **unknown** | - | the base release run has no symbolized in-program stack (see the sanitized pair) |
| finding-security-poc-bit2-256pal-sanitized | Fixed | **unknown** | - | the crash at pnginfo.c:copy_palette disappeared, but no changed function is on its stack; the fix may act through code that returned before the crash |

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
| finding-security-poc-bit1-256pal-release | out-of-scope | no | no | - | release finding has no symbolized location |
| finding-security-poc-bit1-256pal-sanitized | supported | yes | no | - | test has a matchable signature reproduced on the sanitized base |
| finding-security-poc-bit2-256pal-release | out-of-scope | no | no | - | release finding has no symbolized location |
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
| valid-bit1 | release | pass | pass | preserved |
| valid-bit1 | sanitized | pass | pass | preserved |
| boundary-bit4-max | release | pass | pass | preserved |
| boundary-bit4-max | sanitized | pass | pass | preserved |
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
| poc-bit1-256pal | base | release | heap-corruption | glibc-malloc-check | SIGABRT | - | - | confirmed |
| poc-bit1-256pal | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 768 | pnginfo.c:29 in copy_palette | confirmed |
| poc-bit2-256pal | base | release | heap-corruption | glibc-malloc-check | SIGABRT | - | - | confirmed |
| poc-bit2-256pal | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 768 | pnginfo.c:29 in copy_palette | confirmed |
