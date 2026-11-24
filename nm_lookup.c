#include "newminhh_lookup.h"
#include "newminhh_cstd.h"
#include "newminhh_abi.h"
#include "newminhh_log.h"

#include <stdckdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

NM_ASSUME_NONNULL_BEGIN

/* --- Arena allocator --- */

typedef struct nm_arena_block {
    struct nm_arena_block *NM_NULLABLE_PTR next;
    size_t used;
    size_t capacity;
    char data[];
} nm_arena_block_t;

typedef struct {
    nm_arena_block_t *NM_NULLABLE_PTR head;
} nm_arena_t;

static void nm_arena_init(nm_arena_t *a)
{
    a->head = NULL;
}

static void *NM_NULLABLE_PTR nm_arena_alloc(nm_arena_t *a, size_t size)
{
    /* Align up to 8 bytes */
    size_t aligned_sz = (size + 7u) & ~7u;
    if (aligned_sz < size) {
        return NULL;
    }

    if (!a->head || a->head->capacity - a->head->used < aligned_sz) {
        size_t block_cap = 65536;
        if (block_cap < aligned_sz) {
            block_cap = aligned_sz;
        }
        size_t total_alloc = 0;
        if (ckd_add(&total_alloc, sizeof(nm_arena_block_t), block_cap)) {
            return NULL;
        }
        nm_arena_block_t *blk = (nm_arena_block_t *)malloc(total_alloc);
        if (!blk) {
            return NULL;
        }
        blk->next = a->head;
        blk->used = 0;
        blk->capacity = block_cap;
        a->head = blk;
    }

    void *ptr = (void *)(a->head->data + a->head->used);
    a->head->used += aligned_sz;
    return ptr;
}

static const char *NM_NULLABLE_PTR nm_arena_strdup(nm_arena_t *a, const char *s)
{
    size_t len = strlen(s);
    size_t needed = 0;
    if (ckd_add(&needed, len, 1u)) {
        return NULL;
    }
    char *p = (char *)nm_arena_alloc(a, needed);
    if (!p) {
        return NULL;
    }
    memcpy(p, s, len + 1);
    return p;
}

static const char *NM_NULLABLE_PTR nm_arena_strndup(nm_arena_t *a, const char *s, size_t n)
{
    size_t needed = 0;
    if (ckd_add(&needed, n, 1u)) {
        return NULL;
    }
    char *p = (char *)nm_arena_alloc(a, needed);
    if (!p) {
        return NULL;
    }
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

static void nm_arena_free_all(nm_arena_t *a)
{
    nm_arena_block_t *cur = a->head;
    while (cur) {
        nm_arena_block_t *next = cur->next;
        free(cur);
        cur = next;
    }
    a->head = NULL;
}

/* --- Internal record structures --- */

typedef struct {
    const char *path;
    int64_t mtime_ns;
} nm_scan_item_t;

typedef struct {
    const char *i386_soname;
    const char *i386_sym;
    const char *NM_NULLABLE_PTR i386_ver;
    const char *NM_NULLABLE_PTR tgt_soname;
    const char *NM_NULLABLE_PTR tgt_sym;
    const char *NM_NULLABLE_PTR tgt_ver;
    nm_lk_class_t cls;
    uint32_t flags;
    nm_fn_sig_t sig;
    uint32_t size;
    const char *NM_NULLABLE_PTR reason;
} nm_sym_rec_t;

typedef struct {
    uint32_t hash;
    nm_sym_rec_t sym;
} nm_sym_slot_t;

typedef struct {
    const char *i386_soname;
    const char *NM_NULLABLE_PTR path;
    const char *NM_NULLABLE_PTR tgt_soname;
    const char *NM_NULLABLE_PTR tgt_sym;
    nm_lk_class_t cls;
    uint32_t flags;
    const char *NM_NULLABLE_PTR reason;
} nm_lib_rec_t;

typedef struct {
    uint32_t hash;
    nm_lib_rec_t lib;
} nm_lib_slot_t;

struct nm_lookup {
    nm_arena_t arena;
    const char *NM_NULLABLE_PTR generator;
    const char *NM_NULLABLE_PTR libc;
    const char *NM_NULLABLE_PTR interp;
    const char *NM_NULLABLE_PTR rules_hash;

    nm_scan_item_t *NM_NULLABLE_PTR scans;
    size_t num_scans;
    size_t cap_scans;

    nm_sym_slot_t *NM_NULLABLE_PTR sym_slots;
    size_t sym_cap;
    size_t sym_count;

    nm_lib_slot_t *NM_NULLABLE_PTR lib_slots;
    size_t lib_cap;
    size_t lib_count;
};

static inline uint32_t nm_fnv1a(const char *s)
{
    uint32_t h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; ++p) {
        h = (h ^ *p) * 16777619u;
    }
    return (h == 0) ? 1u : h;
}

/* --- Signature Parsing and Formatting --- */

int nm_sig_parse(const char *s, nm_fn_sig_t *out, uint32_t *NM_NULLABLE_PTR out_flags)
{
    if (!s || !out) {
        return NM_ERR_ABI;
    }

    memset(out, 0, sizeof(*out));
    if (out_flags) {
        *out_flags = 0;
    }

    if (s[0] == '\0' || (s[0] == '-' && s[1] == '\0')) {
        return NM_ERR_ABI;
    }

    /* Fixed data/blob: D<n> */
    if (s[0] == 'D') {
        const char *p = s + 1;
        if (*p < '0' || *p > '9') {
            return NM_ERR_ABI;
        }
        unsigned long n = 0;
        while (*p >= '0' && *p <= '9') {
            n = n * 10u + (unsigned long)(*p - '0');
            if (n > 0xFFFFu) {
                return NM_ERR_ABI;
            }
            p++;
        }
        if (*p != '\0') {
            return NM_ERR_ABI;
        }
        out->ret_kind = NM_RET_PTR;
        out->nargs = 0;
        out->abi_ext = (uint8_t)(n > 255u ? 255u : n);
        if (out_flags) {
            *out_flags |= NM_SYM_FLAG_DATA;
        }
        return NM_OK;
    }

    /* Expect <ret>:<args>[...] */
    const char *colon = strchr(s, ':');
    if (!colon) {
        return NM_ERR_ABI;
    }

    /* Parse <ret> */
    if (s[0] == 'S') {
        const char *p = s + 1;
        if (p == colon || *p < '0' || *p > '9') {
            return NM_ERR_ABI;
        }
        unsigned long n = 0;
        while (p < colon && *p >= '0' && *p <= '9') {
            n = n * 10u + (unsigned long)(*p - '0');
            p++;
        }
        if (p != colon || n < 1u || n > 16u) {
            return NM_ERR_ABI;
        }
        out->ret_kind = NM_RET_PTR;
        out->abi_ext = NM_SIG_EXT_MAKE_SRET((uint8_t)n);
    } else if (colon - s == 1) {
        char rc = s[0];
        switch (rc) {
        case 'v': out->ret_kind = NM_RET_VOID; break;
        case 'i': out->ret_kind = NM_RET_I32; break;
        case 'u': out->ret_kind = NM_RET_U32; break;
        case 'p': out->ret_kind = NM_RET_PTR; break;
        case 'q': out->ret_kind = NM_RET_I64; break;
        case 'Q': out->ret_kind = NM_RET_U64; break;
        case 'f': out->ret_kind = NM_RET_F32; break;
        case 'd': out->ret_kind = NM_RET_F64; break;
        default:
            return NM_ERR_ABI; /* Strictly reject 'e', 'A', etc. */
        }
    } else {
        return NM_ERR_ABI;
    }

    /* Parse <args> */
    const char *args = colon + 1;
    size_t arg_len = strlen(args);

    if (arg_len >= 3u && args[arg_len - 3] == '.' && args[arg_len - 2] == '.' && args[arg_len - 1] == '.') {
        out->is_variadic = 1;
        if (out_flags) {
            *out_flags |= NM_SYM_FLAG_VARIADIC;
        }
        arg_len -= 3u;
    }

    if (arg_len > NM_MAX_SIG_ARGS) {
        return NM_ERR_ABI;
    }

    for (size_t i = 0; i < arg_len; ++i) {
        char ac = args[i];
        uint8_t kind = 0;
        switch (ac) {
        case 'i': kind = NM_ARG_I32; break;
        case 'u': kind = NM_ARG_U32; break;
        case 'p': kind = NM_ARG_PTR; break;
        case 'q': kind = NM_ARG_I64; break;
        case 'Q': kind = NM_ARG_U64; break;
        case 'f': kind = NM_ARG_F32; break;
        case 'd': kind = NM_ARG_F64; break;
        default:
            return NM_ERR_ABI; /* Reject 'e', 'A', etc. */
        }
        out->arg_kinds[i] = kind;
    }

    out->nargs = (uint8_t)arg_len;
    return NM_OK;
}

int nm_sig_format(const nm_fn_sig_t *sig, uint32_t flags, char *buf, size_t buf_sz)
{
    if (!sig || !buf || buf_sz == 0) {
        return -1;
    }

    if (flags & NM_SYM_FLAG_DATA) {
        int ret = snprintf(buf, buf_sz, "D%u", (unsigned)sig->abi_ext);
        return (ret >= 0 && (size_t)ret < buf_sz) ? NM_OK : -1;
    }

    char tmp[64];
    size_t pos = 0;

    if (sig->abi_ext & NM_SIG_EXT_SRET) {
        unsigned sret_n = NM_SIG_EXT_SRET_SIZE(sig->abi_ext);
        int ret = snprintf(tmp, sizeof(tmp), "S%u:", sret_n);
        if (ret < 0 || (size_t)ret >= sizeof(tmp)) {
            return -1;
        }
        pos = (size_t)ret;
    } else {
        char rc = '?';
        switch (sig->ret_kind) {
        case NM_RET_VOID: rc = 'v'; break;
        case NM_RET_I32:  rc = 'i'; break;
        case NM_RET_U32:  rc = 'u'; break;
        case NM_RET_PTR:  rc = 'p'; break;
        case NM_RET_I64:  rc = 'q'; break;
        case NM_RET_U64:  rc = 'Q'; break;
        case NM_RET_F32:  rc = 'f'; break;
        case NM_RET_F64:  rc = 'd'; break;
        default: return -1;
        }
        tmp[pos++] = rc;
        tmp[pos++] = ':';
    }

    for (size_t i = 0; i < sig->nargs; ++i) {
        if (pos + 1 >= sizeof(tmp)) {
            return -1;
        }
        char ac = '?';
        switch (sig->arg_kinds[i]) {
        case NM_ARG_I32: ac = 'i'; break;
        case NM_ARG_U32: ac = 'u'; break;
        case NM_ARG_PTR: ac = 'p'; break;
        case NM_ARG_I64: ac = 'q'; break;
        case NM_ARG_U64: ac = 'Q'; break;
        case NM_ARG_F32: ac = 'f'; break;
        case NM_ARG_F64: ac = 'd'; break;
        default: return -1;
        }
        tmp[pos++] = ac;
    }

    if (sig->is_variadic || (flags & NM_SYM_FLAG_VARIADIC)) {
        if (pos + 3 >= sizeof(tmp)) {
            return -1;
        }
        tmp[pos++] = '.';
        tmp[pos++] = '.';
        tmp[pos++] = '.';
    }

    tmp[pos] = '\0';
    if (pos >= buf_sz) {
        return -1;
    }

    memcpy(buf, tmp, pos + 1);
    return NM_OK;
}

/* --- Parse Helpers --- */

static nm_lk_class_t parse_class(const char *s)
{
    if (strcmp(s, "COMPAT") == 0) return NM_LK_COMPAT;
    if (strcmp(s, "NATIVE_TYPED") == 0) return NM_LK_NATIVE_TYPED;
    if (strcmp(s, "NATIVE_DATA") == 0) return NM_LK_NATIVE_DATA;
    if (strcmp(s, "PATCHED_CDECL") == 0) return NM_LK_PATCHED_CDECL;
    if (strcmp(s, "ALIAS") == 0) return NM_LK_ALIAS;
    if (strcmp(s, "UNTYPED") == 0) return NM_LK_UNTYPED;
    if (strcmp(s, "FORBIDDEN_ABI") == 0 || strcmp(s, "FORBIDDEN") == 0) return NM_LK_FORBIDDEN;
    if (strcmp(s, "NATIVE_LIB") == 0 || strcmp(s, "NATIVE") == 0) return NM_LK_NATIVE_LIB;
    return NM_LK_NONE;
}

static uint32_t parse_flag_tokens(const char *str, const char *NM_NULLABLE_PTR *NM_NULLABLE_PTR reason_out, nm_arena_t *arena)
{
    uint32_t flags = 0;
    if (!str || strcmp(str, "-") == 0 || str[0] == '\0') {
        return 0;
    }

    char *buf = strdup(str);
    if (!buf) {
        return 0;
    }

    char *saveptr = NULL;
    char *tok = strtok_r(buf, ", \t", &saveptr);
    while (tok) {
        if (strcmp(tok, "DATA") == 0) {
            flags |= NM_SYM_FLAG_DATA;
        } else if (strcmp(tok, "VARIADIC") == 0) {
            flags |= NM_SYM_FLAG_VARIADIC;
        } else if (strcmp(tok, "CDECL_DIRECT") == 0) {
            flags |= NM_SYM_FLAG_CDECL_DIRECT;
        } else if (strcmp(tok, "IFUNC") == 0) {
            flags |= NM_SYM_FLAG_IFUNC;
        } else if (strcmp(tok, "NATIVE") == 0) {
            flags |= NM_SYM_FLAG_NATIVE;
        } else if (strcmp(tok, "PATCHED") == 0) {
            flags |= NM_SYM_FLAG_PATCHED;
        } else if (strcmp(tok, "STATIC_ONLY") == 0) {
            flags |= NM_SYM_FLAG_STATIC_ONLY;
        } else if (strcmp(tok, "RUNTIME_ONLY") == 0) {
            flags |= NM_SYM_FLAG_RUNTIME_ONLY;
        } else if (strcmp(tok, "WEAK") == 0) {
            flags |= NM_SYM_FLAG_WEAK;
        } else if (strcmp(tok, "PURE") == 0) {
            flags |= NM_SYM_FLAG_PURE;
        } else if (strncmp(tok, "REASON=", 7) == 0) {
            if (reason_out) {
                *reason_out = nm_arena_strdup(arena, tok + 7);
            }
        }
        tok = strtok_r(NULL, ", \t", &saveptr);
    }

    free(buf);
    return flags;
}

static void split_sym_ver(const char *in,
                          const char *NM_NULLABLE_PTR *NM_NONNULL_PTR sym_out,
                          const char *NM_NULLABLE_PTR *NM_NONNULL_PTR ver_out,
                          nm_arena_t *arena)
{
    if (strcmp(in, "-") == 0 || in[0] == '\0') {
        *sym_out = NULL;
        *ver_out = NULL;
        return;
    }

    const char *at = strchr(in, '@');
    if (at) {
        size_t n = (size_t)(at - in);
        *sym_out = nm_arena_strndup(arena, in, n);
        *ver_out = nm_arena_strdup(arena, at + 1);
    } else {
        *sym_out = nm_arena_strdup(arena, in);
        *ver_out = NULL;
    }
}

/* Round up to next power of 2 */
static size_t next_pow2(size_t v)
{
    if (v <= 16u) return 16u;
    size_t p = 16u;
    while (p < v) {
        size_t next_p = 0;
        if (ckd_mul(&next_p, p, 2u)) {
            return p;
        }
        p = next_p;
    }
    return p;
}

/* --- nm_lookup_open_mem --- */

int nm_lookup_open_mem(const char *data, size_t len, nm_lookup_t **out)
{
    if (!data || !out) {
        return NM_ERR_ABI;
    }

    *out = NULL;

    /* Verify line 1 header magic */
    size_t magic_len = strlen(NM_LOOKUP_HEADER_MAGIC);
    if (len < magic_len || memcmp(data, NM_LOOKUP_HEADER_MAGIC, magic_len) != 0) {
        NM_LOG_ERROR("lookup", "invalid header: must begin with '%s'", NM_LOOKUP_HEADER_MAGIC);
        return NM_ERR_ELF;
    }

    /* Pass 1: count lines, sym records, lib records, and scan directives */
    size_t count_sym = 0;
    size_t count_lib = 0;
    size_t count_scan = 0;

    const char *p = data;
    const char *end = data + len;

    while (p < end) {
        const char *line_start = p;
        while (p < end && *p != '\n' && *p != '\r') {
            p++;
        }
        size_t line_len = (size_t)(p - line_start);
        while (p < end && (*p == '\n' || *p == '\r')) {
            p++;
        }

        if (line_len >= 4 && memcmp(line_start, "sym\t", 4) == 0) {
            count_sym++;
        } else if (line_len >= 4 && memcmp(line_start, "lib\t", 4) == 0) {
            count_lib++;
        } else if (line_len >= 6 && memcmp(line_start, "#@scan", 6) == 0) {
            count_scan++;
        }
    }

    nm_lookup_t *lk = (nm_lookup_t *)calloc(1, sizeof(nm_lookup_t));
    if (!lk) {
        return NM_ERR_ABI;
    }
    nm_arena_init(&lk->arena);

    /* Allocate hash tables with open addressing (target load factor ~0.5) */
    size_t sym_cap_need = 0;
    if (ckd_mul(&sym_cap_need, count_sym, 2u) || ckd_add(&sym_cap_need, sym_cap_need, 16u)) {
        free(lk);
        return NM_ERR_ABI;
    }
    lk->sym_cap = next_pow2(sym_cap_need);

    size_t sym_alloc = 0;
    if (ckd_mul(&sym_alloc, lk->sym_cap, sizeof(nm_sym_slot_t))) {
        free(lk);
        return NM_ERR_ABI;
    }
    lk->sym_slots = (nm_sym_slot_t *)calloc(1, sym_alloc);
    if (!lk->sym_slots) {
        free(lk);
        return NM_ERR_ABI;
    }

    size_t lib_cap_need = 0;
    if (ckd_mul(&lib_cap_need, count_lib, 2u) || ckd_add(&lib_cap_need, lib_cap_need, 16u)) {
        free(lk->sym_slots);
        free(lk);
        return NM_ERR_ABI;
    }
    lk->lib_cap = next_pow2(lib_cap_need);

    size_t lib_alloc = 0;
    if (ckd_mul(&lib_alloc, lk->lib_cap, sizeof(nm_lib_slot_t))) {
        free(lk->sym_slots);
        free(lk);
        return NM_ERR_ABI;
    }
    lk->lib_slots = (nm_lib_slot_t *)calloc(1, lib_alloc);
    if (!lk->lib_slots) {
        free(lk->sym_slots);
        free(lk);
        return NM_ERR_ABI;
    }

    if (count_scan > 0) {
        size_t scan_alloc = 0;
        if (ckd_mul(&scan_alloc, count_scan, sizeof(nm_scan_item_t))) {
            nm_lookup_close(lk);
            return NM_ERR_ABI;
        }
        lk->scans = (nm_scan_item_t *)calloc(1, scan_alloc);
        if (!lk->scans) {
            nm_lookup_close(lk);
            return NM_ERR_ABI;
        }
        lk->cap_scans = count_scan;
    }

    /* Pass 2: parse records */
    p = data;
    size_t line_no = 0;

    while (p < end) {
        line_no++;
        const char *line_start = p;
        while (p < end && *p != '\n' && *p != '\r') {
            p++;
        }
        size_t line_len = (size_t)(p - line_start);
        while (p < end && (*p == '\n' || *p == '\r')) {
            p++;
        }

        if (line_len == 0) {
            continue;
        }

        /* Check for metadata lines (#@...) */
        if (line_len >= 2 && line_start[0] == '#' && line_start[1] == '@') {
            char line_buf[1024];
            size_t copy_len = (line_len < sizeof(line_buf) - 1) ? line_len : sizeof(line_buf) - 1;
            memcpy(line_buf, line_start, copy_len);
            line_buf[copy_len] = '\0';

            char *tag = line_buf + 2;
            char *sep = strpbrk(tag, " \t");
            if (sep) {
                *sep = '\0';
                char *val = sep + 1;
                while (*val == ' ' || *val == '\t') val++;

                if (strcmp(tag, "generator") == 0) {
                    lk->generator = nm_arena_strdup(&lk->arena, val);
                } else if (strcmp(tag, "libc") == 0) {
                    char *space = strpbrk(val, " \t");
                    if (space) *space = '\0';
                    lk->libc = nm_arena_strdup(&lk->arena, val);
                } else if (strcmp(tag, "interp") == 0) {
                    char *space = strpbrk(val, " \t");
                    if (space) *space = '\0';
                    lk->interp = nm_arena_strdup(&lk->arena, val);
                } else if (strcmp(tag, "rules") == 0) {
                    lk->rules_hash = nm_arena_strdup(&lk->arena, val);
                } else if (strcmp(tag, "scan") == 0) {
                    char *mtime_str = strpbrk(val, " \t");
                    if (mtime_str) {
                        *mtime_str = '\0';
                        mtime_str++;
                        while (*mtime_str == ' ' || *mtime_str == '\t') mtime_str++;
                        if (lk->num_scans < lk->cap_scans) {
                            lk->scans[lk->num_scans].path = nm_arena_strdup(&lk->arena, val);
                            lk->scans[lk->num_scans].mtime_ns = strtoll(mtime_str, NULL, 10);
                            lk->num_scans++;
                        }
                    }
                }
            }
            continue;
        }

        /* Skip comments */
        if (line_start[0] == '#') {
            continue;
        }

        /* 9-column tab-separated records */
        char line_buf[2048];
        size_t copy_len = (line_len < sizeof(line_buf) - 1) ? line_len : sizeof(line_buf) - 1;
        memcpy(line_buf, line_start, copy_len);
        line_buf[copy_len] = '\0';

        char *cols[16];
        size_t col_cnt = 0;
        char *cur = line_buf;
        while (cur && col_cnt < 16) {
            cols[col_cnt++] = cur;
            char *tab = strchr(cur, '\t');
            if (!tab) {
                break;
            }
            *tab = '\0';
            cur = tab + 1;
        }

        if (col_cnt < 9) {
            NM_LOG_ERROR("lookup", "line %zu: expected 9 columns, found %zu", line_no, col_cnt);
            nm_lookup_close(lk);
            return NM_ERR_ABI;
        }

        const char *rec_type = cols[0];
        if (strcmp(rec_type, "lib") == 0) {
            const char *i386_soname = nm_arena_strdup(&lk->arena, cols[1]);
            const char *path = (strcmp(cols[2], "-") == 0) ? NULL : nm_arena_strdup(&lk->arena, cols[2]);
            const char *tgt_soname = (strcmp(cols[3], "-") == 0) ? NULL : nm_arena_strdup(&lk->arena, cols[3]);
            const char *tgt_sym = (strcmp(cols[4], "-") == 0) ? NULL : nm_arena_strdup(&lk->arena, cols[4]);
            nm_lk_class_t cls = parse_class(cols[5]);

            const char *reason = NULL;
            uint32_t flags = parse_flag_tokens(cols[7], &reason, &lk->arena);

            /* Insert into lib_slots */
            uint32_t h = nm_fnv1a(i386_soname);
            size_t idx = h & (lk->lib_cap - 1);
            while (lk->lib_slots[idx].hash != 0) {
                idx = (idx + 1) & (lk->lib_cap - 1);
            }
            lk->lib_slots[idx].hash = h;
            lk->lib_slots[idx].lib.i386_soname = i386_soname;
            lk->lib_slots[idx].lib.path = path;
            lk->lib_slots[idx].lib.tgt_soname = tgt_soname;
            lk->lib_slots[idx].lib.tgt_sym = tgt_sym;
            lk->lib_slots[idx].lib.cls = cls;
            lk->lib_slots[idx].lib.flags = flags;
            lk->lib_slots[idx].lib.reason = reason;
            lk->lib_count++;

        } else if (strcmp(rec_type, "sym") == 0) {
            const char *i386_soname = nm_arena_strdup(&lk->arena, cols[1]);
            const char *i386_sym = NULL;
            const char *i386_ver = NULL;
            split_sym_ver(cols[2], &i386_sym, &i386_ver, &lk->arena);
            if (!i386_sym) {
                NM_LOG_ERROR("lookup", "line %zu: missing symbol name in column 3", line_no);
                nm_lookup_close(lk);
                return NM_ERR_ABI;
            }

            const char *tgt_soname = (strcmp(cols[3], "-") == 0) ? NULL : nm_arena_strdup(&lk->arena, cols[3]);
            const char *tgt_sym = NULL;
            const char *tgt_ver = NULL;
            split_sym_ver(cols[4], &tgt_sym, &tgt_ver, &lk->arena);

            nm_lk_class_t cls = parse_class(cols[5]);
            if (cls == NM_LK_NONE && strcmp(cols[5], "-") != 0 && strcmp(cols[5], "NONE") != 0) {
                NM_LOG_ERROR("lookup", "line %zu: unrecognized class '%s'", line_no, cols[5]);
                nm_lookup_close(lk);
                return NM_ERR_ABI;
            }

            const char *reason = NULL;
            uint32_t flags = parse_flag_tokens(cols[7], &reason, &lk->arena);

            nm_fn_sig_t sig;
            memset(&sig, 0, sizeof(sig));
            if (strcmp(cols[6], "-") != 0 && cols[6][0] != '\0') {
                uint32_t sig_flags = 0;
                if (nm_sig_parse(cols[6], &sig, &sig_flags) != NM_OK) {
                    NM_LOG_ERROR("lookup", "line %zu: invalid signature '%s'", line_no, cols[6]);
                    nm_lookup_close(lk);
                    return NM_ERR_ABI;
                }
                flags |= sig_flags;
            }

            uint32_t size = 0;
            if (strcmp(cols[8], "-") != 0 && cols[8][0] != '\0') {
                size = (uint32_t)strtoul(cols[8], NULL, 10);
            }

            /* Insert into sym_slots */
            uint32_t h = nm_fnv1a(i386_sym);
            size_t idx = h & (lk->sym_cap - 1);
            while (lk->sym_slots[idx].hash != 0) {
                idx = (idx + 1) & (lk->sym_cap - 1);
            }
            lk->sym_slots[idx].hash = h;
            lk->sym_slots[idx].sym.i386_soname = i386_soname;
            lk->sym_slots[idx].sym.i386_sym = i386_sym;
            lk->sym_slots[idx].sym.i386_ver = i386_ver;
            lk->sym_slots[idx].sym.tgt_soname = tgt_soname;
            lk->sym_slots[idx].sym.tgt_sym = tgt_sym;
            lk->sym_slots[idx].sym.tgt_ver = tgt_ver;
            lk->sym_slots[idx].sym.cls = cls;
            lk->sym_slots[idx].sym.flags = flags;
            lk->sym_slots[idx].sym.sig = sig;
            lk->sym_slots[idx].sym.size = size;
            lk->sym_slots[idx].sym.reason = reason;
            lk->sym_count++;
        } else {
            NM_LOG_ERROR("lookup", "line %zu: unknown record type '%s'", line_no, rec_type);
            nm_lookup_close(lk);
            return NM_ERR_ABI;
        }
    }

    *out = lk;
    return NM_OK;
}

int nm_lookup_open(const char *path, nm_lookup_t **out)
{
    if (!path || !out) {
        return NM_ERR_ABI;
    }

    *out = NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return NM_ERR_ABI;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return NM_ERR_ABI;
    }

    size_t sz = (size_t)st.st_size;
    size_t alloc_sz = 0;
    if (ckd_add(&alloc_sz, sz, 1u)) {
        close(fd);
        return NM_ERR_ABI;
    }

    char *buf = (char *)malloc(alloc_sz);
    if (!buf) {
        close(fd);
        return NM_ERR_ABI;
    }

    size_t total = 0;
    while (total < sz) {
        ssize_t rd = read(fd, buf + total, sz - total);
        if (rd < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return NM_ERR_ABI;
        }
        if (rd == 0) break;
        total += (size_t)rd;
    }
    close(fd);
    buf[total] = '\0';

    int rc = nm_lookup_open_mem(buf, total, out);
    free(buf);
    return rc;
}

/* --- Internal Lookup Helper --- */

static const nm_sym_rec_t *NM_NULLABLE_PTR nm_find_best_sym(const nm_lookup_t *lk,
                                                             const char *NM_NULLABLE_PTR soname,
                                                             const char *sym,
                                                             const char *NM_NULLABLE_PTR ver,
                                                             uint32_t mode_mask)
{
    if (!lk->sym_slots || lk->sym_cap == 0) {
        return NULL;
    }

    uint32_t h = nm_fnv1a(sym);
    size_t idx = h & (lk->sym_cap - 1);
    const nm_sym_rec_t *best = NULL;
    int best_pri = 999;

    while (lk->sym_slots[idx].hash != 0) {
        if (lk->sym_slots[idx].hash == h &&
            strcmp(lk->sym_slots[idx].sym.i386_sym, sym) == 0) {

            const nm_sym_rec_t *cand = &lk->sym_slots[idx].sym;

            /* Filter by mode_mask */
            bool skip = false;
            if (mode_mask & NM_SYM_FLAG_STATIC_ONLY) {
                if (cand->flags & NM_SYM_FLAG_RUNTIME_ONLY) {
                    skip = true;
                }
            } else {
                /* mode_mask == 0 (runtime default) or NM_SYM_FLAG_RUNTIME_ONLY */
                if (cand->flags & NM_SYM_FLAG_STATIC_ONLY) {
                    skip = true;
                }
            }

            if (!skip) {
                int pri = 0;
                bool is_wild = (strcmp(cand->i386_soname, "*") == 0);
                bool soname_match = (soname != NULL && strcmp(cand->i386_soname, soname) == 0);

                if (soname_match && ver != NULL && cand->i386_ver != NULL && strcmp(cand->i386_ver, ver) == 0) {
                    pri = 1;
                } else if (soname_match && cand->i386_ver == NULL) {
                    pri = 2;
                } else if (is_wild && ver != NULL && cand->i386_ver != NULL && strcmp(cand->i386_ver, ver) == 0) {
                    pri = 3;
                } else if (is_wild && cand->i386_ver == NULL) {
                    pri = 4;
                }

                if (pri > 0 && pri < best_pri) {
                    best = cand;
                    best_pri = pri;
                    if (pri == 1) {
                        break; /* Cannot beat Priority 1 */
                    }
                }
            }
        }
        idx = (idx + 1) & (lk->sym_cap - 1);
    }

    return best;
}

int nm_lookup_find(const nm_lookup_t *lk,
                   const char *NM_NULLABLE_PTR soname,
                   const char *sym,
                   const char *NM_NULLABLE_PTR ver,
                   uint32_t mode_mask,
                   nm_lk_entry_t *out)
{
    if (!lk || !sym || !out) {
        return NM_ERR_DLSYM;
    }

    const char *cur_soname = soname;
    const char *cur_sym = sym;
    const char *cur_ver = ver;

    for (int depth = 0; depth < 5; ++depth) {
        const nm_sym_rec_t *cand = nm_find_best_sym(lk, cur_soname, cur_sym, cur_ver, mode_mask);
        if (!cand) {
            return NM_ERR_DLSYM;
        }

        if (cand->cls != NM_LK_ALIAS) {
            out->cls = cand->cls;
            out->flags = cand->flags;
            out->sig = cand->sig;
            out->size = cand->size;
            out->tgt_soname = cand->tgt_soname;
            out->tgt_sym = cand->tgt_sym;
            out->tgt_ver = cand->tgt_ver;
            out->reason = cand->reason;
            return NM_OK;
        }

        /* Follow alias (max depth 4) */
        if (depth >= 4) {
            return NM_ERR_DLSYM;
        }

        if (cand->tgt_soname && strcmp(cand->tgt_soname, "-") != 0) {
            cur_soname = cand->tgt_soname;
        }
        if (!cand->tgt_sym || strcmp(cand->tgt_sym, "-") == 0) {
            return NM_ERR_DLSYM;
        }
        cur_sym = cand->tgt_sym;
        cur_ver = cand->tgt_ver;
    }

    return NM_ERR_DLSYM;
}

int nm_lookup_find_lib(const nm_lookup_t *lk,
                       const char *soname,
                       nm_lk_entry_t *out,
                       const char *NM_NULLABLE_PTR *NM_NULLABLE_PTR path_out)
{
    if (!lk || !soname || !out) {
        return NM_ERR_DLSYM;
    }

    if (!lk->lib_slots || lk->lib_cap == 0) {
        return NM_ERR_DLSYM;
    }

    uint32_t h = nm_fnv1a(soname);
    size_t idx = h & (lk->lib_cap - 1);

    while (lk->lib_slots[idx].hash != 0) {
        if (lk->lib_slots[idx].hash == h &&
            strcmp(lk->lib_slots[idx].lib.i386_soname, soname) == 0) {

            const nm_lib_rec_t *lib = &lk->lib_slots[idx].lib;
            out->cls = lib->cls;
            out->flags = lib->flags;
            memset(&out->sig, 0, sizeof(out->sig));
            out->size = 0;
            out->tgt_soname = lib->tgt_soname;
            out->tgt_sym = lib->tgt_sym;
            out->tgt_ver = NULL;
            out->reason = lib->reason;
            if (path_out) {
                *path_out = lib->path;
            }
            return NM_OK;
        }
        idx = (idx + 1) & (lk->lib_cap - 1);
    }

    return NM_ERR_DLSYM;
}

const char *NM_NULLABLE_PTR nm_lookup_interp(const nm_lookup_t *lk)
{
    return lk ? lk->interp : NULL;
}

const char *NM_NULLABLE_PTR nm_lookup_libc(const nm_lookup_t *lk)
{
    return lk ? lk->libc : NULL;
}

int nm_lookup_is_stale(const nm_lookup_t *lk)
{
    if (!lk) {
        return 1;
    }

    for (size_t i = 0; i < lk->num_scans; ++i) {
        struct stat st;
        int64_t cur_mtime = 0;
        if (stat(lk->scans[i].path, &st) == 0 && S_ISDIR(st.st_mode)) {
            cur_mtime = (int64_t)st.st_mtim.tv_sec * 1000000000LL + (int64_t)st.st_mtim.tv_nsec;
        }
        if (cur_mtime != lk->scans[i].mtime_ns) {
            return 1;
        }
    }

    return 0;
}

void nm_lookup_close(nm_lookup_t *NM_NULLABLE_PTR lk)
{
    if (!lk) {
        return;
    }
    nm_arena_free_all(&lk->arena);
    free(lk->scans);
    free(lk->sym_slots);
    free(lk->lib_slots);
    free(lk);
}

NM_ASSUME_NONNULL_END
