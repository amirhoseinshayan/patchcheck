# Patchcheck: giflib

**Verdict: 0 PASS**

Versions: base `a0924ed046` → candidate `0393990a1e`
Builds: 4; tests: 8; executions: 68.

| Axis | Result |
|---|---|
| Security | fixed (target reproduced on base: yes) |
| Functional | preserved |
| Analysis complete | yes |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Fixed | heap-buffer-overflow | asan | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed | stable | finding-security-poc-bg-oob-sanitized |
| Fixed | heap-buffer-overflow | asan | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed | stable | finding-security-poc-bg-far-sanitized |
| Fixed | heap-buffer-overflow | asan | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed | stable | finding-security-generated-f277902e97e8a227-sanitized |

## Patch correlation

Confirmed relationships cite a relevant stack frame or a covered changed line in the matching version. Unknown relationships lack sufficient evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-security-poc-bg-oob-sanitized | Fixed | **confirmed** | h5 | h5 changes util/gif2rgb.c:GIF2RGB, the caller (frame #1) of the base failure; h5 changes util/gif2rgb.c:GIF2RGB, the allocation-stack (frame #1) of the base failure; hunks outside any function (not mapped): h1, h3; the same input crashes base at util/gif2rgb.c:DumpScreen2RGB and not the candidate |
| finding-security-poc-bg-far-sanitized | Fixed | **confirmed** | h5 | h5 changes util/gif2rgb.c:GIF2RGB, the caller (frame #1) of the base failure; h5 changes util/gif2rgb.c:GIF2RGB, the allocation-stack (frame #1) of the base failure; hunks outside any function (not mapped): h1, h3; the same input crashes base at util/gif2rgb.c:DumpScreen2RGB and not the candidate |
| finding-security-generated-f277902e97e8a227-sanitized | Fixed | **confirmed** | h5 | h5 changes util/gif2rgb.c:GIF2RGB, the caller (frame #1) of the base failure; h5 changes util/gif2rgb.c:GIF2RGB, the allocation-stack (frame #1) of the base failure; hunks outside any function (not mapped): h1, h3; the same input crashes base at util/gif2rgb.c:DumpScreen2RGB and not the candidate |

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
| finding-security-poc-bg-oob-sanitized | supported | yes | no | - | test has a matchable signature reproduced on the sanitized base |
| finding-security-poc-bg-far-sanitized | supported | yes | no | - | test has a matchable signature reproduced on the sanitized base |
| finding-security-generated-f277902e97e8a227-sanitized | supported | yes | no | - | test has a matchable signature reproduced on the sanitized base |

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
| valid-fill | release | pass | pass | preserved |
| valid-fill | sanitized | pass | pass | preserved |
| valid-margin | release | pass | pass | preserved |
| valid-margin | sanitized | pass | pass | preserved |
| boundary-bg-max | release | pass | pass | preserved |
| boundary-bg-max | sanitized | pass | pass | preserved |
| invalid-oversize | release | pass | pass | preserved |
| invalid-oversize | sanitized | pass | pass | preserved |
| invalid-zero-dim | release | pass | pass | preserved |
| invalid-zero-dim | sanitized | pass | pass | preserved |
| poc-bg-oob | release | fail | pass | baseline_fail |
| poc-bg-oob | sanitized | fail | pass | baseline_fail |
| poc-bg-far | release | fail | pass | baseline_fail |
| poc-bg-far | sanitized | fail | pass | baseline_fail |
| generated-f277902e97e8a227 | release | fail | pass | baseline_fail |
| generated-f277902e97e8a227 | sanitized | fail | pass | baseline_fail |

## Crash classification

| Test | Version | Build | Error type | Detection | Termination | Access | Location | Evidence |
|---|---|---|---|---|---|---|---|---|
| poc-bg-oob | base | sanitized | heap-buffer-overflow | asan | SIGABRT | READ 1 | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed |
| poc-bg-far | base | sanitized | heap-buffer-overflow | asan | SIGABRT | READ 1 | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed |
| generated-f277902e97e8a227 | base | sanitized | heap-buffer-overflow | asan | SIGABRT | READ 1 | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed |
