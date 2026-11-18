# Patchcheck: libpng

**Verdict: 0 PASS**

Versions: base `6397ff5fbe` → candidate `ef91189fb8`
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
| finding-security-poc-bit1-256pal-sanitized | Fixed | **confirmed** | h438, h507 | h438 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, base); h507 changes pngset.c:png_set_PLTE, called from main on the stack but not itself on the failing stack; hunks outside any function (not mapped): h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, h30, h31, h33, h34, h35, h42, h43, h44, h70, h71, h80, h81, h83, h84, h88, h90, h94, h97, h99, h100, h105, h113, h115, h116, h117, h118, h129, h130, h134, h137, h138, h144, h153, h161, h179, h182, h183, h184, h185, h186, h187, h197, h274, h293, h294, h323, h324, h330, h344, h345, h346, h347, h350, h352, h353, h354, h355, h356, h357, h358, h359, h360, h361, h362, h364, h365, h366, h367, h368, h369, h370, h371, h372, h373, h374, h375, h376, h377, h378, h379, h380, h381, h382, h383, h384, h385, h386, h387, h388, h390, h391, h392, h393, h394, h395, h396, h397, h398, h399, h400, h401, h402, h403, h404, h405, h406, h407, h408, h409, h410, h411, h412, h413, h414, h416, h438, h443, h444, h445, h448, h449, h450, h453, h456, h457, h458, h459, h460, h472, h494, h511, h513, h514, h515, h516, h530, h547, h549, h550, h551, h552, h553, h554, h555, h556, h557, h558, h559, h560, h561, h565, h566, h567, h568, h569, h570, h571, h572, h573, h574, h575, h576, h577, h578, h579, h580, h581, h582, h583, h584, h585, h586, h587, h588, h589, h590, h591, h592, h593, h594, h595, h596, h597, h598, h599, h600, h601, h602, h603, h604, h605, h606, h607, h608, h609, h610, h611, h612, h613, h614, h615; the same input crashes base at pnginfo.c:copy_palette and not the candidate |
| finding-security-poc-bit2-256pal-sanitized | Fixed | **confirmed** | h438, h507 | h438 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, base); h507 changes pngset.c:png_set_PLTE, called from main on the stack but not itself on the failing stack; hunks outside any function (not mapped): h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, h30, h31, h33, h34, h35, h42, h43, h44, h70, h71, h80, h81, h83, h84, h88, h90, h94, h97, h99, h100, h105, h113, h115, h116, h117, h118, h129, h130, h134, h137, h138, h144, h153, h161, h179, h182, h183, h184, h185, h186, h187, h197, h274, h293, h294, h323, h324, h330, h344, h345, h346, h347, h350, h352, h353, h354, h355, h356, h357, h358, h359, h360, h361, h362, h364, h365, h366, h367, h368, h369, h370, h371, h372, h373, h374, h375, h376, h377, h378, h379, h380, h381, h382, h383, h384, h385, h386, h387, h388, h390, h391, h392, h393, h394, h395, h396, h397, h398, h399, h400, h401, h402, h403, h404, h405, h406, h407, h408, h409, h410, h411, h412, h413, h414, h416, h438, h443, h444, h445, h448, h449, h450, h453, h456, h457, h458, h459, h460, h472, h494, h511, h513, h514, h515, h516, h530, h547, h549, h550, h551, h552, h553, h554, h555, h556, h557, h558, h559, h560, h561, h565, h566, h567, h568, h569, h570, h571, h572, h573, h574, h575, h576, h577, h578, h579, h580, h581, h582, h583, h584, h585, h586, h587, h588, h589, h590, h591, h592, h593, h594, h595, h596, h597, h598, h599, h600, h601, h602, h603, h604, h605, h606, h607, h608, h609, h610, h611, h612, h613, h614, h615; the same input crashes base at pnginfo.c:copy_palette and not the candidate |

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
