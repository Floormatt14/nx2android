// The runtime .ips/.ips32 parser's regression fixture (tests/test_mods_code.py compiles it with the real parse_ips,
// sliced out of nxnative/dm/host/mods_code.c). The shims stand in for dm.h's LOG / die and the record list, so the
// parser compiles alone; parse_records parses one patch file and exports its records' image offsets and lengths.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define die(...) do { fprintf(stderr, __VA_ARGS__); exit(3); } while (0)
#define LOG(...) fprintf(stderr, __VA_ARGS__)

typedef struct { uint64_t off; const uint8_t *p; uint32_t n; uint8_t rle; } mrec;

static void push(mrec **r, int *n, int *cap, uint64_t off, const uint8_t *p, uint32_t len, uint8_t rle) {
    if (*n == *cap) { *cap = *cap ? *cap * 2 : 64; *r = realloc(*r, (size_t)*cap * sizeof **r); if (!*r) die("[code] out of memory"); }
    (*r)[*n] = (mrec){off, p, len, rle}; (*n)++;
}

static int refuse(const char *file, const char *why) { fprintf(stderr, "[RED] [code] %s: %s; the file is skipped\n", file, why); return -1; }

// ---- below this line the test appends mods_code.c's parse_ips ----

long parse_records(const char *path, uint64_t *offs, uint32_t *lens, long cap) {
    FILE *f = fopen(path, "rb"); if (!f) return -2;
    static uint8_t buf[1 << 20]; size_t n = fread(buf, 1, sizeof buf, f); fclose(f);
    mrec *r = NULL; int nr = 0, c = 0;
    if (parse_ips(path, buf, n, &r, &nr, &c) < 0) { free(r); return -1; }   // the file is refused whole, as mods_file does
    long k = 0;
    for (; k < nr && k < cap; k++) { offs[k] = r[k].off; lens[k] = r[k].n; }
    free(r);
    return nr;
}
