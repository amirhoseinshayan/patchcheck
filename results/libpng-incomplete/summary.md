# Patchcheck: libpng

**Verdict: 10 VULN_REMAINS / NEW_ISSUE**

Versions: base `6397ff5fbe` → candidate `af9e6baf43`
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
| finding-security-poc-bit1-256pal-sanitized | Incomplete Fix | **confirmed** | h396, h452 | h396 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, base); h396 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, candidate); h452 changes pngset.c:png_set_PLTE, called from main on the stack but not itself on the failing stack; hunks outside any function (not mapped): h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, h24, h25, h27, h28, h34, h35, h36, h60, h68, h70, h71, h74, h76, h80, h83, h84, h86, h87, h88, h96, h98, h99, h100, h101, h112, h113, h117, h120, h121, h131, h149, h152, h153, h154, h155, h156, h157, h167, h248, h265, h266, h267, h274, h294, h295, h296, h307, h308, h309, h310, h313, h315, h316, h317, h318, h319, h320, h321, h322, h323, h324, h325, h326, h327, h328, h329, h330, h331, h332, h333, h334, h335, h336, h337, h338, h339, h340, h341, h342, h343, h344, h345, h346, h347, h348, h349, h350, h351, h352, h353, h354, h355, h356, h357, h358, h359, h360, h361, h362, h363, h364, h365, h366, h367, h368, h369, h370, h371, h372, h373, h375, h396, h401, h402, h403, h406, h407, h408, h411, h414, h415, h416, h417, h418, h457, h475, h489, h491, h492, h493, h494, h495, h496, h497, h498, h499, h500, h501, h502, h503, h507, h508, h509, h510, h511, h512, h513, h514, h515, h516, h517, h518, h519, h520, h521, h522, h523, h524, h525, h526, h527, h528, h529, h530, h531, h532, h533, h534, h535, h536, h537, h538, h539, h540, h541, h542, h543, h544, h545, h546, h547, h548, h549, h550, h551, h552, h553, h554, h555, h556, h557; the patch changes the failing path but the same failure at pnginfo.c:copy_palette persists on the candidate |
| finding-security-poc-bit2-256pal-sanitized | Incomplete Fix | **confirmed** | h396, h452 | h396 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, base); h396 changes macro PNG_LIBPNG_VER_STRING used by pnginfo.c:main (frame #2, candidate); h452 changes pngset.c:png_set_PLTE, called from main on the stack but not itself on the failing stack; hunks outside any function (not mapped): h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, h24, h25, h27, h28, h34, h35, h36, h60, h68, h70, h71, h74, h76, h80, h83, h84, h86, h87, h88, h96, h98, h99, h100, h101, h112, h113, h117, h120, h121, h131, h149, h152, h153, h154, h155, h156, h157, h167, h248, h265, h266, h267, h274, h294, h295, h296, h307, h308, h309, h310, h313, h315, h316, h317, h318, h319, h320, h321, h322, h323, h324, h325, h326, h327, h328, h329, h330, h331, h332, h333, h334, h335, h336, h337, h338, h339, h340, h341, h342, h343, h344, h345, h346, h347, h348, h349, h350, h351, h352, h353, h354, h355, h356, h357, h358, h359, h360, h361, h362, h363, h364, h365, h366, h367, h368, h369, h370, h371, h372, h373, h375, h396, h401, h402, h403, h406, h407, h408, h411, h414, h415, h416, h417, h418, h457, h475, h489, h491, h492, h493, h494, h495, h496, h497, h498, h499, h500, h501, h502, h503, h507, h508, h509, h510, h511, h512, h513, h514, h515, h516, h517, h518, h519, h520, h521, h522, h523, h524, h525, h526, h527, h528, h529, h530, h531, h532, h533, h534, h535, h536, h537, h538, h539, h540, h541, h542, h543, h544, h545, h546, h547, h548, h549, h550, h551, h552, h553, h554, h555, h556, h557; the patch changes the failing path but the same failure at pnginfo.c:copy_palette persists on the candidate |

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
