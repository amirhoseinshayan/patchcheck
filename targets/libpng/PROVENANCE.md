# libpng target provenance

Upstream: libpng, https://github.com/pnggroup/libpng (PNG reference library).
Libpng license, see `COPYING`.

Vulnerability: **CVE-2015-8126**, and its incomplete fix **CVE-2015-8472**.
`png_set_PLTE` / `png_get_PLTE` did not clamp the palette size to the image bit
depth, so a palette PNG with a small bit depth (1/2/4) could carry up to 256
palette entries. A correctly-written application that sizes its palette buffer
from the bit depth (`1 << bit_depth`) then copies the reported `num_palette`
entries, overflowing the buffer. The upstream fix for the read path landed in
libpng 1.6.19 (`png_handle_PLTE` truncates the palette to `1 << bit_depth`); the
follow-up CVE-2015-8472 recorded that the 1.6.19 fix was itself incomplete for
the `png_set_PLTE` API path (it compared `png_ptr->color_type/bit_depth` instead
of `info_ptr->…`), completed in 1.6.20.

| Version | Source |
|---|---|
| `base` | upstream libpng 1.6.18 (`v1.6.18`), vulnerable |
| `correct` | `base` with the CVE-2015-8126 fix applied to `png_handle_PLTE` (truncate to `1 << bit_depth`) and the matching clamp in `png_set_PLTE` — the security-relevant hunks of the real 1.6.19 fix |
| `incomplete` | `base` with the clamp narrowed to reject only the observed bit-depth-1 case; bit depths 2 and 4 still accept an oversized palette, so a *different* input still overflows (models CVE-2015-8472's "incomplete fix") |
| `regression` | `correct` with an over-strict extra clamp that truncates valid 8-bit (256-entry) palettes to 128 entries (our edit) |

Only the minimal source needed to build `pnginfo` is kept: the 15 libpng
translation units (`png.c`, `pngerror.c`, `pngget.c`, `pngmem.c`, `pngpread.c`,
`pngread.c`, `pngrio.c`, `pngrtran.c`, `pngrutil.c`, `pngset.c`, `pngtrans.c`,
`pngwio.c`, `pngwrite.c`, `pngwtran.c`, `pngwutil.c`), the public/private headers
and a generated `pnglibconf.h`, plus the `pnginfo.c` driver. The build links
against the system zlib (`-lz`) and libm (`-lm`). `git diff base correct` in
`.fixture-repos/libpng` reproduces exactly the CVE-2015-8126 palette-size fix.
