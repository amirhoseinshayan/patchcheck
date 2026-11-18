#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "png.h"

/* Silent error/warning handlers: the driver reports a single fixed message so
 * the independent oracle can match exact output regardless of libpng's own
 * version-dependent diagnostics. */
static void silent_error(png_structp png, png_const_charp msg) {
    (void)msg;
    png_longjmp(png, 1);
}

static void silent_warning(png_structp png, png_const_charp msg) {
    (void)png;
    (void)msg;
}

/* Copy the palette into a buffer whose size is the correct maximum for the bit
 * depth (1 << bit_depth). libpng before the fix reports up to 256 entries
 * regardless of bit depth, so the copy overflows the correctly-sized buffer.
 * The release build's FORTIFY_SOURCE catches this as a buffer overflow; the
 * sanitized build's AddressSanitizer reports a heap-buffer-overflow WRITE. */
static void copy_palette(png_colorp pal, int n, int bit_depth) {
    int correct = 1 << bit_depth;
    png_colorp buf = (png_colorp)malloc((size_t)correct * sizeof(png_color));
    if (!buf) exit(2);
    memcpy(buf, pal, (size_t)n * sizeof(png_color));
    volatile unsigned long sink = 0;
    int i;
    for (i = 0; i < n; i++)
        sink += (unsigned char)buf[i].red + (unsigned char)buf[i].green + (unsigned char)buf[i].blue;
    (void)sink;
    free(buf);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: pnginfo FILE\n"); return 2; }
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { fprintf(stderr, "open failed\n"); return 2; }

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, silent_error, silent_warning);
    if (!png) return 2;
    png_infop info = png_create_info_struct(png);
    if (!info) return 2;

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        fprintf(stderr, "png error\n");
        return 1;
    }

    png_init_io(png, fp);
    png_read_info(png, info);

    png_uint_32 width = png_get_image_width(png, info);
    png_uint_32 height = png_get_image_height(png, info);
    int bit_depth = png_get_bit_depth(png, info);
    int color_type = png_get_color_type(png, info);

    png_bytepp rows = (png_bytepp)malloc((size_t)height * sizeof(png_bytep));
    if (!rows) return 2;
    {
        png_uint_32 y;
        for (y = 0; y < height; y++)
            rows[y] = (png_bytep)malloc(png_get_rowbytes(png, info));
    }
    png_read_image(png, rows);

    int num_palette = 0;
    if (color_type == PNG_COLOR_TYPE_PALETTE) {
        png_colorp pal = NULL;
        int n = 0;
        if (png_get_PLTE(png, info, &pal, &n) && pal != NULL && n > 0) {
            num_palette = n;
            copy_palette(pal, n, bit_depth);
        }
    }

    printf("OK %u %u %d %d %d\n", width, height, bit_depth, color_type, num_palette);

    {
        png_uint_32 y;
        for (y = 0; y < height; y++) free(rows[y]);
    }
    free(rows);
    png_read_end(png, NULL);
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
    return 0;
}
