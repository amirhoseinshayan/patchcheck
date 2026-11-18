# libpng target provenance

Upstream: libpng, https://github.com/pnggroup/libpng (PNG reference library).
Libpng license, see `COPYING`.

Vulnerability: **CVE-2015-8126**, and its **incomplete fix CVE-2015-8472**.
`png_set_PLTE` / `png_get_PLTE` did not clamp the palette size to the image bit
depth, so a palette PNG with a small bit depth (1/2/4) could carry up to 256
palette entries. A correctly-written application that sizes its palette buffer
from the bit depth (`1 << bit_depth`) then copies the reported `num_palette`
entries, overflowing the buffer.

This target reproduces the **real upstream incomplete-fix sequence**:

| Version | Source |
|---|---|
| `base` | upstream libpng **1.6.18** (`v1.6.18`) — vulnerable: `png_set_PLTE` has no bit-depth clamp, and the read path (`png_handle_PLTE`) does not truncate the palette |
| `incomplete` | upstream libpng **1.6.19** (`v1.6.19`) — the real, incomplete fix: `png_handle_PLTE` now truncates to `1 << bit_depth` (fixing CVE-2015-8126 on the read path), but `png_set_PLTE` still computes the maximum from `png_ptr->color_type/bit_depth` instead of `info_ptr->…`, so an application that calls `png_set_PLTE` directly is still not protected → **CVE-2015-8472** |
| `correct` | upstream libpng **1.6.20** (`libpng-1.6.20-signed`) — the complete fix: `png_set_PLTE` uses `info_ptr->color_type/bit_depth` |
| `regression` | `correct` with an over-strict extra clamp that truncates valid 8-bit (256-entry) palettes to 128 entries (our edit, as the assignment requires a group-designed functional regression) |

`git diff base correct` in `.fixture-repos/libpng` reproduces the upstream
1.6.18 → 1.6.20 history (the palette-size fixes plus the same release's unrelated
hardening changes); `git diff incomplete correct` is exactly the CVE-2015-8472
fix (`png_ptr` → `info_ptr`).

The `pnginfo.c` driver reads a PNG and then re-encodes it through the public
`png_set_PLTE` API with a 256-entry palette, so the incomplete fix of 1.6.19 is
exercised dynamically (not just the read path).

Each `targets/libpng/<version>/` folder is the **complete upstream source tree**
of that version (every file from the upstream tag: all translation units,
headers, `scripts/`, `contrib/`, `arm/`, `projects/`, `tests/`, build files and
docs), plus our `pnginfo.c` driver and a top-level `pnglibconf.h` copied from
`scripts/pnglibconf.h.prebuilt` (the header `configure` would generate). The
build only compiles the 15 read/write translation units and the driver, listed in
`configs/libpng-file.json`, and links system zlib (`-lz`) and libm (`-lm`).
