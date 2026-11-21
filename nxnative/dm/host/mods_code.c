// Runtime code mods: the Mods panel's (dm/android/front_android.c) mod folders' exefs/ code layers, applied at load
// time. front_android.c mods_apply composes DM_CODE_MODS (the mod folders, priority order) and loader.c map_image
// calls mods_code_apply() while the module's image is copied and still writable, then mods_code_seal() after its
// mprotects seal the text. A folder's exefs/ holds .pchtxt sections ([NSO:<32-hex build id> [title id]], entries of a
// hex address then hex byte pairs; @disabled marks an entry off, @next-off <hex> addresses byte-only lines, // comments
// are stripped) and .ips / .ips32 patches named by build ID (the IPS32 terminator is EEOF, an .ips's is EOF, either only
// recognized as the trailing bytes). Only records whose build ID matches the module's (the rewriter fixups header's
// BUILD_ID) apply. A record on the host's own machinery (the key page or the patch area), past the image, or on bytes a
// port-time cut already changed (<name>.cuts.tsv: registered patches, FPSLocker and --mods cuts all land there), on a
// rewritten site (<name>.sites.tsv) or on an observation gate refuses
// the whole file with [RED]: a bad mod degrades to the unpatched module, never a crash. Mod-written pages stay RWX so
// mods that re-patch themselves at run time keep working; DM_MODS_RWX=0 seals them like the rest of the text. Apple has
// no Mods panel: this file is built on Android only (dm/host/Makefile leaves it out). Modules the game loads later
// (loader.c's NROs) do not take code mods yet.
#include "dm.h"
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>

#define CODE_PAGE 0x4000ull   // the loader's page size (map_image seals in 16 KB pages)

static int hexv(int c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

static int bid_eq(const char *a, const char *b) {   // two 32-hex-digit build IDs, case-insensitive
    for (int i = 0; i < 32; i++) if (hexv((unsigned char)a[i]) < 0 || (a[i] | 32) != (b[i] | 32)) return 0;
    return !a[32] && !b[32];
}

typedef struct { uint64_t off; const uint8_t *p; uint32_t n; uint8_t rle; } mrec;   // rle: p[0] repeated n times

static void push(mrec **r, int *n, int *cap, uint64_t off, const uint8_t *p, uint32_t len, uint8_t rle) {
    if (*n == *cap) { *cap = *cap ? *cap * 2 : 64; *r = realloc(*r, (size_t)*cap * sizeof **r); if (!*r) die("[code] out of memory"); }
    (*r)[*n] = (mrec){off, p, len, rle}; (*n)++;
}

static int refuse(const char *file, const char *why) { LOG("[RED] [code] %s: %s; the file is skipped", file, why); return -1; }
static const char *code_base(const char *p) { const char *b = strrchr(p, '/'); return b && b[1] ? b + 1 : p; }

// ---- the bytes the rewriter already changed, which a runtime record must not touch: <name>.cuts.tsv (registered patches,
// FPSLocker and --mods cuts), <name>.sites.tsv (every guest instruction rewritten in place: plain sites, W windows, J and T
// jump sites, S spin sites and their back-edges — the T and J rows' targets are diagnostics only, the original table and
// branch targets stay as they are), <name>.obs.tsv (observation gates) ----
typedef struct { uint64_t off, len; } crange;
static crange *g_prot; static int g_nprot, g_prot_cap;
static void add_prot(uint64_t off, uint64_t len) {
    if (g_nprot == g_prot_cap) { g_prot_cap = g_prot_cap ? g_prot_cap * 2 : 4096; g_prot = realloc(g_prot, (size_t)g_prot_cap * sizeof *g_prot); if (!g_prot) die("[code] out of memory"); }
    g_prot[g_nprot].off = off; g_prot[g_nprot].len = len; g_nprot++;
}
static void add_prot4(uint64_t off) { if (off) add_prot(off, 4); }
static void load_protected(const char *dir, const char *name) {
    g_nprot = 0;
    char path[1024];
    snprintf(path, sizeof path, "%s/%s.cuts.tsv", dir, name);
    FILE *f = fopen(path, "r");
    if (f) { char line[512];
        while (fgets(line, sizeof line, f)) {
            if (*line == '#') continue;
            unsigned long long off; char ob[128];
            if (sscanf(line, "%llx%*[ \t]%127s", &off, ob) == 2) add_prot(off, strlen(ob) / 2);
        }
        fclose(f);
    }
    snprintf(path, sizeof path, "%s/%s.sites.tsv", dir, name);
    f = fopen(path, "r");
    if (f) { char line[1024];
        while (fgets(line, sizeof line, f)) {
            char *t[3] = {0}; int nt = 0;
            for (char *s = line; nt < 3; ) { while (*s == '\t') s++; t[nt++] = s; char *e = strchr(s, '\t'); if (!e) break; *e = 0; s = e + 1; }
            if (!t[0][0] || *t[0] == '#') continue;
            unsigned long long a = strtoull(t[0], NULL, 16);
            if (!t[1][0]) continue;
            if (t[1][0] == 'W' && t[2][0]) { unsigned long long end = strtoull(t[2], NULL, 16); if (end > a) add_prot(a, end - a); continue; }   // a rewritten window
            add_prot4(a);   // the rewritten instruction itself
            if (t[1][0] == 'S') for (char *s = t[2]; *s; ) { char *e = strchr(s, ' '); if (e) *e = 0; add_prot4(strtoull(s, NULL, 16)); if (!e) break; s = e + 1; }   // a spin site's back-edges branch into its patch-area copy
        }
        fclose(f);
    }
    snprintf(path, sizeof path, "%s/%s.obs.tsv", dir, name);
    f = fopen(path, "r");
    if (f) { char line[512];
        while (fgets(line, sizeof line, f)) {
            if (*line == '#') continue;
            unsigned long long off; int oid, ow;
            if (sscanf(line, "%llx\t%d\t%d", &off, &oid, &ow) >= 1) add_prot4(off);
        }
        fclose(f);
    }
}
static int on_prot(uint64_t off, uint64_t len) {
    for (int i = 0; i < g_nprot; i++)
        if (off < g_prot[i].off + g_prot[i].len && g_prot[i].off < off + len) return 1;
    return 0;
}

// ---- .pchtxt: sections gated by build ID, entries collected only for this module's; a malformed line refuses the file.
// An entry line's byte tokens are contiguous addresses, so they merge into one record (through a per-file byte blob) ----
static uint8_t g_blob[1 << 20]; static size_t g_bln;
static int parse_pchtxt(module_t *m, const char *file, const uint8_t *d, size_t n, mrec **r, int *nr, int *cap) {
    int sec = 0; uint64_t next = (uint64_t)-1; g_bln = 0;
    for (size_t i = 0; i < n; ) {
        size_t e = i; while (e < n && d[e] != '\n') e++;
        for (size_t k = i; k + 1 < e; k++) if (d[k] == '/' && d[k + 1] == '/') { e = k; break; }   // a // comment
        size_t j = i; while (j < e && (d[j] == ' ' || d[j] == '\t')) j++;
        if (j < e && d[j] == '[') {   // a section header: [NSO:<32 hex build id> [anything else, e.g. the title id]]
            sec = 0;
            const char *h = strstr((const char *)d + j, "NSO:");
            if (h) { char b[33]; int k = 0; h += 4; while (k < 32 && hexv((unsigned char)h[k]) >= 0) b[k++] = h[k]; b[k] = 0; sec = k == 32 && bid_eq(b, m->build_id); }
        } else if (j < e && d[j] == '@') {   // @disabled <entry>: parsed, not recorded; @next-off <hex>; anything else ignored
            const char *no = strstr((const char *)d + j, "@next-off");
            unsigned long long v; if (no && sscanf(no + 9, " %llx", &v) == 1) next = v;
        } else if (j < e) {   // an entry: a hex address, then hex byte pairs; a byte-only line takes (and advances) @next-off
            int dis = !strncmp((const char *)d + j, "@disabled", 9), has = 0; uint64_t addr = 0; size_t t = j;
            if (dis) { t = j + 9; while (t < e && (d[t] == ' ' || d[t] == '\t')) t++; }
            size_t ts = t; while (t < e && d[t] != ' ' && d[t] != '\t') t++;
            for (size_t k = ts; k < t; k++) if (hexv(d[k]) < 0) return refuse(file, "a line holds a non-hex character");
            if (t < e) {   // more tokens follow: the first token is the address
                if (t - ts > 16) return refuse(file, "an address is longer than 16 hex digits");
                for (size_t k = ts; k < t; k++) addr = addr << 4 | (unsigned)hexv(d[k]); has = 1;
                while (t < e && (d[t] == ' ' || d[t] == '\t')) t++;
            } else if (next != (uint64_t)-1) { addr = next; has = 1; }
            if (!has && dis) { i = e + 1; continue; }   // a bare @disabled line
            if (!has) return refuse(file, "an entry has no address (@next-off unset)");
            size_t base = g_bln;
            while (t < e) {
                size_t s = t; while (t < e && d[t] != ' ' && d[t] != '\t') t++;
                size_t l = t - s;
                if (l) {
                    if (l & 1) return refuse(file, "an entry's byte run has an odd number of hex digits");
                    for (size_t k = s; k < t; k++) if (hexv(d[k]) < 0) return refuse(file, "a line holds a non-hex character");
                    if (sec && !dis) {
                        if (g_bln + l / 2 > sizeof g_blob) return refuse(file, "the file's patch bytes do not fit (1 MB)");
                        memcpy(g_blob + g_bln, d + s, l / 2); g_bln += l / 2;
                    }
                    addr += l / 2;
                    if (next != (uint64_t)-1 && !dis) next += l / 2;
                }
                while (t < e && (d[t] == ' ' || d[t] == '\t')) t++;
            }
            if (sec && !dis && g_bln > base) push(r, nr, cap, addr - (g_bln - base), g_blob + base, (uint32_t)(g_bln - base), 0);
        }
        i = e + 1;
    }
    return 0;
}

// ---- .ips / .ips32: the whole file is one module's patches, named by its build ID. Records are Atmosphere ExeFS file
// offsets: the 0x100-byte NSO header is cut off (mods_layer.py's bake does the same; .pchtxt records are image offsets and do not) ----
static int parse_ips(const char *file, const uint8_t *d, size_t n, mrec **r, int *nr, int *cap) {
    int ol; size_t i;
    if (n > 5 && !memcmp(d, "IPS32", 5)) { ol = 4; i = 5; }
    else if (n > 3 && !memcmp(d, "IPS", 3)) { ol = 3; i = 3; }
    else return refuse(file, "not an IPS or IPS32 patch");
    while (i < n) {
        if (n - i == (size_t)ol && !memcmp(d + i, ol == 4 ? "EEOF" : "EOF", (size_t)ol)) break;
        if (i + (size_t)ol + 2 > n) return refuse(file, "truncated before a record's bytes");
        uint64_t off = 0; for (int k = 0; k < ol; k++) off = off << 8 | d[i + k]; i += (size_t)ol;
        if (off < 0x100) return refuse(file, "a record patches the NSO header, not the memory image");
        off -= 0x100;   // Atmosphere ExeFS IPS file offsets include the 0x100-byte NSO header; the image starts after it (mods_layer.py's bake cuts the same bias: the two halves' contract, verified against a real mod's .ips against its bake's rows)
        uint32_t ln = (uint32_t)(d[i] << 8 | d[i + 1]); i += 2;
        if (!ln) {   // RLE: one byte, then its run count
            if (i + 3 > n) return refuse(file, "truncated inside a run record");
            uint32_t run = (uint32_t)(d[i + 1] << 8 | d[i + 2]); push(r, nr, cap, off, d + i, run, 1); i += 3;
        } else {
            if (i + ln > n) return refuse(file, "truncated inside a record");
            push(r, nr, cap, off, d + i, ln, 0); i += ln;
        }
    }
    return 0;
}

// ---- apply one folder's exefs/ to one module ----
static int ok_range(module_t *m, uint64_t off, uint64_t len, const char *file) {
    if (off + len <= off || off + len > m->size) { refuse(file, "a record runs past the module's image"); return 0; }
    if (off < m->key_page_off + m->key_page_size && m->key_page_off < off + len) { refuse(file, "a record is on the host's key page"); return 0; }
    if (m->fps_state_off && off < m->fps_state_off + 0x40 && m->fps_state_off < off + len) { refuse(file, "a record is on the host's frame step state page"); return 0; }
    if (m->patch_off > 0 && off + len > (uint64_t)m->patch_off) { refuse(file, "a record is on the host's patch area"); return 0; }
    if (on_prot(off, len)) { refuse(file, "a record is on bytes the rewriter changed (a port-time cut, a rewritten site or an observation gate)"); return 0; }
    return 1;
}
static uint64_t g_pages[512]; static int g_np;
static void mods_file(module_t *m, const char *label, const char *path, int ips) {
    FILE *f = fopen(path, "rb"); if (!f) return;   // raced out or unreadable: no layer from it, the game boots unpatched
    static uint8_t buf[16 << 20]; size_t n = fread(buf, 1, sizeof buf - 1, f); buf[n] = 0; int over = fgetc(f) != EOF; fclose(f);
    if (over) { refuse(label, "the file is larger than 16 MB"); return; }
    mrec *r = NULL; int nr = 0, cap = 0, fail = 0;
    if (ips) fail = parse_ips(label, buf, n, &r, &nr, &cap) < 0;
    else fail = parse_pchtxt(m, label, buf, n, &r, &nr, &cap) < 0;
    if (fail || !nr) { free(r); return; }   // empty: the file targets other modules
    for (int i = 0; i < nr; i++) if (!ok_range(m, r[i].off, r[i].n, label)) fail = 1;
    if (fail) { free(r); return; }
    for (int i = 0; i < nr; i++) {
        if (r[i].rle) memset(m->base + r[i].off, r[i].p[0], r[i].n); else memcpy(m->base + r[i].off, r[i].p, r[i].n);
        for (uint64_t pg = r[i].off & ~(CODE_PAGE - 1); pg < ((r[i].off + r[i].n + CODE_PAGE - 1) & ~(CODE_PAGE - 1)); pg += CODE_PAGE) {
            int k = 0; while (k < g_np && g_pages[k] != pg) k++;
            if (k == g_np && g_np < (int)(sizeof g_pages / sizeof g_pages[0])) g_pages[g_np++] = pg;
        }
    }
    LOG("[code] %s: %d record(s) on %s", label, nr, m->name);
    free(r);
}
// A whole-module replacement (a bare NSO file named by module, e.g. Luminescent Platinum's exefs/subsdk1) is baked at port
// time only (dm/tools/patch_nso.py's DM_MODULE_SRC), never at run time. A folder whose exefs/ replaces a module this port
// does not load has an incomplete code layer — its patched main would call into the original module it was not written for
// — so the whole folder is refused, exactly as porter/mods_layer.py refuses it at port time.
static int file_nso(const char *dir, const char *nm) {   // the file starts with the NSO0 magic
    char p[900]; snprintf(p, sizeof p, "%s/%s", dir, nm);
    FILE *f = fopen(p, "rb"); if (!f) return 0;
    uint8_t m4[4] = {0}; size_t r = fread(m4, 1, 4, f); fclose(f);
    return r == 4 && !memcmp(m4, "NSO0", 4);
}
static void mods_folder(module_t *m, const char *folder, const char **names, int nn) {
    char x[800]; snprintf(x, sizeof x, "%s/exefs", folder);
    DIR *d = opendir(x); if (!d) return;   // the folder has no code layer
    struct dirent *e;
    while ((e = readdir(d))) {   // pass 1: an unknown module replacement refuses the folder whole
        size_t nl = strlen(e->d_name); const char *nm = e->d_name;
        if (nl > 4 && (!strcasecmp(nm + nl - 4, ".ips") || (nl > 6 && !strcasecmp(nm + nl - 6, ".ips32")) || (nl > 7 && !strcasecmp(nm + nl - 7, ".pchtxt")))) continue;
        if (!file_nso(x, nm)) continue;
        char stem[64]; snprintf(stem, sizeof stem, "%.*s", (int)nl, nm);
        int known = 0; for (int i = 0; i < nn; i++) if (!strcasecmp(names[i], stem)) { known = 1; break; }
        if (!known) { LOG("[RED] [code] %s/exefs/%s: replaces %s, which this port does not load: the mod's code layer is incomplete; its files are skipped", code_base(folder), nm, stem); closedir(d); return; }
    }
    rewinddir(d);
    while ((e = readdir(d))) {   // pass 2: the patch files
        size_t nl = strlen(e->d_name); const char *nm = e->d_name;
        int ips = nl > 4 && (!strcasecmp(nm + nl - 4, ".ips") || (nl > 6 && !strcasecmp(nm + nl - 6, ".ips32")));
        int txt = nl > 7 && !strcasecmp(nm + nl - 7, ".pchtxt");
        if (!ips && !txt) continue;
        if (ips) {   // named by the module's build ID: another module's file is skipped quietly
            int ext = nl > 6 && !strcasecmp(nm + nl - 6, ".ips32") ? 6 : 4;
            char stem[64]; snprintf(stem, sizeof stem, "%.*s", (int)(nl - ext), nm);
            if (!bid_eq(stem, m->build_id)) continue;
        }
        char p[900]; snprintf(p, sizeof p, "%s/%s", x, nm);
        char label[1000]; snprintf(label, sizeof label, "%s/exefs/%s", code_base(folder), nm);
        mods_file(m, label, p, ips);
    }
    closedir(d);
}

// loader.c map_image, after the image is copied in and before its text is sealed. names are the port's modules (loader.c
// load_modules's list): a folder replacing an unknown one is refused whole.
void mods_code_apply(module_t *m, const char *dir, const char **names, int nn) {
    g_np = 0;
    const char *env = getenv("DM_CODE_MODS"); if (!env || !*env) return;
    load_protected(dir, m->name);
    char mods[2048]; snprintf(mods, sizeof mods, "%s", env);
    for (char *f = mods; *f; ) {
        char *c = strchr(f, ':'); if (c) *c = 0;
        mods_folder(m, f, names, nn);
        if (c) f = c + 1; else break;
    }
}

// loader.c map_image, after the text is sealed: mod-written pages stay RWX (DM_MODS_RWX=0 seals them like the rest)
void mods_code_seal(module_t *m) {
    if (!g_np) return;
    const char *env = getenv("DM_MODS_RWX");
    if (env && !strcmp(env, "0")) { LOG("[code] %s: %d mod-written page(s) sealed like the rest (DM_MODS_RWX=0)", m->name, g_np); return; }
    for (int i = 0; i < g_np; i++)
        if (mprotect(m->base + g_pages[i], CODE_PAGE, PROT_READ | PROT_WRITE | PROT_EXEC)) LOG("[RED] [code] %s: a mod-written page could not be made RWX", m->name);
    LOG("[code] %s: %d mod-written page(s) left RWX", m->name, g_np);
}
