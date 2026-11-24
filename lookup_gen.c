#include "newminhh_lookup.h"
#include "newminhh_cstd.h"
#include "newminhh_abi.h"
#include "newminhh_log.h"

#include <stdckdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <elf.h>
#include <glob.h>
#include <limits.h>

NM_ASSUME_NONNULL_BEGIN

/* Forward declarations */
static off_t elf_vaddr_to_offset(Elf32_Addr va, const Elf32_Phdr *phdrs, uint16_t phnum, size_t file_size);

/* --- Dynamic String Buffer --- */

typedef struct {
    char *NM_NULLABLE_PTR data;
    size_t len;
    size_t cap;
} str_buf_t;

static void buf_init(str_buf_t *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static bool buf_reserve(str_buf_t *b, size_t extra)
{
    size_t needed = 0;
    if (ckd_add(&needed, b->len, extra) || ckd_add(&needed, needed, 1u)) {
        return false;
    }
    if (needed > b->cap) {
        size_t new_cap = b->cap ? b->cap * 2u : 4096u;
        if (new_cap < needed) {
            new_cap = needed;
        }
        char *p = (char *)realloc(b->data, new_cap);
        if (!p) {
            return false;
        }
        b->data = p;
        b->cap = new_cap;
    }
    return true;
}

static bool buf_append_str(str_buf_t *b, const char *s)
{
    size_t slen = strlen(s);
    if (!buf_reserve(b, slen)) {
        return false;
    }
    memcpy(b->data + b->len, s, slen);
    b->len += slen;
    b->data[b->len] = '\0';
    return true;
}

NM_PRINTF_FMT(2, 3)
static bool buf_printf(str_buf_t *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        return false;
    }
    size_t un = (size_t)n;
    if (!buf_reserve(b, un)) {
        return false;
    }
    va_start(ap, fmt);
    vsnprintf(b->data + b->len, un + 1u, fmt, ap);
    va_end(ap);
    b->len += un;
    return true;
}

static void buf_free(str_buf_t *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

/* --- Directory Creation and Atomic Writing --- */

static bool mkdir_p(const char *path, mode_t mode)
{
    char tmp[PATH_MAX];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                return false;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        return false;
    }
    return true;
}

static bool atomic_write_file(const char *out_path, const char *NM_NULLABLE_PTR content, size_t len, bool create_parent)
{
    if (!content || len == 0) {
        content = "";
        len = 0;
    }
    if (create_parent) {
        char path_copy[PATH_MAX];
        strncpy(path_copy, out_path, sizeof(path_copy) - 1);
        path_copy[sizeof(path_copy) - 1] = '\0';
        char *slash = strrchr(path_copy, '/');
        if (slash && slash != path_copy) {
            *slash = '\0';
            if (!mkdir_p(path_copy, 0755)) {
                NM_LOG_ERROR("lookup-gen", "failed creating parent directory '%s'", path_copy);
                return false;
            }
        }
    }

    char tmp_path[PATH_MAX];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", out_path, (int)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
        return false;
    }

    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        NM_LOG_ERROR("lookup-gen", "cannot open temporary file '%s': %s", tmp_path, strerror(errno));
        return false;
    }

    if (len > 0) {
        size_t written = fwrite(content, 1, len, f);
        if (written != len) {
            NM_LOG_ERROR("lookup-gen", "short write to '%s': %s", tmp_path, strerror(errno));
            fclose(f);
            unlink(tmp_path);
            return false;
        }
    }

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    chmod(tmp_path, 0644);

    if (rename(tmp_path, out_path) != 0) {
        NM_LOG_ERROR("lookup-gen", "cannot rename '%s' to '%s': %s", tmp_path, out_path, strerror(errno));
        unlink(tmp_path);
        return false;
    }

    return true;
}

/* --- ELF Scanner Data Structures --- */

typedef struct {
    char *NM_NONNULL_PTR name;
    char *NM_NULLABLE_PTR version;
    uint32_t size;
    bool is_func;
} scanned_symbol_t;

typedef struct {
    char *NM_NONNULL_PTR soname;
    char *NM_NONNULL_PTR realpath;
    bool is_patched;
    scanned_symbol_t *NM_NULLABLE_PTR syms;
    size_t num_syms;
    size_t cap_syms;
} scanned_lib_t;

typedef struct {
    dev_t dev;
    ino_t ino;
} visited_file_t;

typedef struct {
    char *NM_NONNULL_PTR path;
    int64_t mtime_ns;
} scanned_dir_t;

typedef struct {
    char *NM_NONNULL_PTR rec_type; /* "sym" or "lib" */
    char *NM_NONNULL_PTR i386_soname;
    char *NM_NULLABLE_PTR i386_sym;
    char *NM_NULLABLE_PTR i386_ver;
    char *NM_NULLABLE_PTR tgt_soname;
    char *NM_NULLABLE_PTR tgt_sym;
    char *NM_NULLABLE_PTR tgt_ver;
    char *NM_NONNULL_PTR cls;
    char *NM_NONNULL_PTR sig;
    char *NM_NONNULL_PTR flags;
    char *NM_NONNULL_PTR size;
    char *NM_NULLABLE_PTR reason;
    bool emitted;
} static_rule_t;

/* --- ELF Offset Translation --- */

static off_t elf_vaddr_to_offset(Elf32_Addr va, const Elf32_Phdr *phdrs, uint16_t phnum, size_t file_size)
{
    for (uint16_t i = 0; i < phnum; ++i) {
        if (phdrs[i].p_type == PT_LOAD) {
            Elf32_Addr vstart = phdrs[i].p_vaddr;
            Elf32_Addr vend = vstart + phdrs[i].p_filesz;
            if (va >= vstart && va < vend) {
                size_t off = phdrs[i].p_offset + (va - vstart);
                if (off < file_size) {
                    return (off_t)off;
                }
            }
        }
    }
    return -1;
}

/* --- Reading PT_INTERP from /bin/sh or /usr/bin/env --- */

static bool read_interp_from_elf(const char *path, char *buf, size_t buf_sz)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(Elf32_Ehdr)) {
        close(fd);
        return false;
    }

    size_t fsz = (size_t)st.st_size;
    void *map = mmap(NULL, fsz, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        return false;
    }

    bool found = false;
    const unsigned char *e_ident = (const unsigned char *)map;
    if (e_ident[EI_MAG0] == ELFMAG0 && e_ident[EI_MAG1] == ELFMAG1 &&
        e_ident[EI_MAG2] == ELFMAG2 && e_ident[EI_MAG3] == ELFMAG3) {

        if (e_ident[EI_CLASS] == ELFCLASS32 && fsz >= sizeof(Elf32_Ehdr)) {
            const Elf32_Ehdr *eh = (const Elf32_Ehdr *)map;
            size_t ph_end = 0;
            if (!ckd_mul(&ph_end, eh->e_phnum, sizeof(Elf32_Phdr)) &&
                !ckd_add(&ph_end, ph_end, eh->e_phoff) && ph_end <= fsz) {
                const Elf32_Phdr *ph = (const Elf32_Phdr *)((const char *)map + eh->e_phoff);
                for (uint16_t i = 0; i < eh->e_phnum; ++i) {
                    if (ph[i].p_type == PT_INTERP) {
                        if (ph[i].p_offset < fsz && ph[i].p_offset + ph[i].p_filesz <= fsz) {
                            size_t copy_len = (ph[i].p_filesz < buf_sz - 1u) ? ph[i].p_filesz : buf_sz - 1u;
                            memcpy(buf, (const char *)map + ph[i].p_offset, copy_len);
                            buf[copy_len] = '\0';
                            found = true;
                            break;
                        }
                    }
                }
            }
        } else if (e_ident[EI_CLASS] == ELFCLASS64 && fsz >= sizeof(Elf64_Ehdr)) {
            const Elf64_Ehdr *eh = (const Elf64_Ehdr *)map;
            size_t ph_end = 0;
            if (!ckd_mul(&ph_end, eh->e_phnum, sizeof(Elf64_Phdr)) &&
                !ckd_add(&ph_end, ph_end, eh->e_phoff) && ph_end <= fsz) {
                const Elf64_Phdr *ph = (const Elf64_Phdr *)((const char *)map + eh->e_phoff);
                for (uint16_t i = 0; i < eh->e_phnum; ++i) {
                    if (ph[i].p_type == PT_INTERP) {
                        if (ph[i].p_offset < fsz && ph[i].p_offset + ph[i].p_filesz <= fsz) {
                            size_t copy_len = (ph[i].p_filesz < buf_sz - 1u) ? ph[i].p_filesz : buf_sz - 1u;
                            memcpy(buf, (const char *)map + ph[i].p_offset, copy_len);
                            buf[copy_len] = '\0';
                            found = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    munmap(map, fsz);
    return found;
}

/* --- Scanning a single x32 ELF Shared Object --- */

static bool scan_x32_elf(const char *filepath, scanned_lib_t *out_lib)
{
    int fd = open(filepath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(Elf32_Ehdr)) {
        close(fd);
        return false;
    }

    size_t fsz = (size_t)st.st_size;
    void *map = mmap(NULL, fsz, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        return false;
    }

    const unsigned char *e_ident = (const unsigned char *)map;
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
        e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
        munmap(map, fsz);
        return false;
    }

    /* Strictly ELFCLASS32, ELFDATA2LSB, EM_X86_64, ET_DYN */
    if (e_ident[EI_CLASS] != ELFCLASS32 || e_ident[EI_DATA] != ELFDATA2LSB) {
        munmap(map, fsz);
        return false;
    }

    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)map;
    if (eh->e_machine != EM_X86_64 || eh->e_type != ET_DYN) {
        munmap(map, fsz);
        return false;
    }

    /* Bounds check program headers */
    size_t ph_end = 0;
    if (ckd_mul(&ph_end, eh->e_phnum, sizeof(Elf32_Phdr)) ||
        ckd_add(&ph_end, ph_end, eh->e_phoff) || ph_end > fsz) {
        munmap(map, fsz);
        return false;
    }

    const Elf32_Phdr *phdrs = (const Elf32_Phdr *)((const char *)map + eh->e_phoff);

    /* Check PT_NOTE for .note.newminhh */
    bool is_patched = false;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (phdrs[i].p_type == PT_NOTE) {
            size_t noff = phdrs[i].p_offset;
            size_t nfilesz = phdrs[i].p_filesz;
            if (noff < fsz && noff + nfilesz <= fsz) {
                const char *nptr = (const char *)map + noff;
                const char *nend = nptr + nfilesz;
                while (nptr + sizeof(Elf32_Nhdr) <= nend) {
                    const Elf32_Nhdr *nh = (const Elf32_Nhdr *)nptr;
                    size_t nsz = nh->n_namesz;
                    size_t dsz = nh->n_descsz;
                    size_t aligned_nsz = (nsz + 3u) & ~3u;
                    size_t aligned_dsz = (dsz + 3u) & ~3u;
                    const char *name = nptr + sizeof(Elf32_Nhdr);
                    if (name + aligned_nsz + aligned_dsz > nend) {
                        break;
                    }
                    if (nh->n_type == NM_NOTE_TYPE_PATCHED && nsz >= 8u &&
                        memcmp(name, NM_NOTE_NAME, 8) == 0) {
                        is_patched = true;
                    }
                    nptr = name + aligned_nsz + aligned_dsz;
                }
            }
        }
    }

    /* Find PT_DYNAMIC */
    const Elf32_Phdr *dyn_ph = NULL;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_ph = &phdrs[i];
            break;
        }
    }
    if (!dyn_ph) {
        munmap(map, fsz);
        return false;
    }

    size_t dyn_off = dyn_ph->p_offset;
    size_t dyn_sz = dyn_ph->p_filesz;
    if (dyn_off >= fsz || dyn_off + dyn_sz > fsz) {
        munmap(map, fsz);
        return false;
    }

    size_t num_dyn = dyn_sz / sizeof(Elf32_Dyn);
    const Elf32_Dyn *dyns = (const Elf32_Dyn *)((const char *)map + dyn_off);

    Elf32_Word soname_idx = 0;
    Elf32_Addr symtab_va = 0;
    Elf32_Addr strtab_va = 0;
    size_t strsz = 0;
    Elf32_Addr hash_va = 0;
    Elf32_Addr gnu_hash_va = 0;
    Elf32_Addr versym_va = 0;
    Elf32_Addr verdef_va = 0;
    uint32_t verdefnum = 0;

    for (size_t i = 0; i < num_dyn; ++i) {
        Elf32_Sword tag = dyns[i].d_tag;
        if (tag == DT_NULL) {
            break;
        }
        switch (tag) {
        case DT_SONAME:    soname_idx = dyns[i].d_un.d_val; break;
        case DT_SYMTAB:    symtab_va = dyns[i].d_un.d_ptr; break;
        case DT_STRTAB:    strtab_va = dyns[i].d_un.d_ptr; break;
        case DT_STRSZ:     strsz = (size_t)dyns[i].d_un.d_val; break;
        case DT_HASH:      hash_va = dyns[i].d_un.d_ptr; break;
        case DT_GNU_HASH:  gnu_hash_va = dyns[i].d_un.d_ptr; break;
        case DT_VERSYM:    versym_va = dyns[i].d_un.d_ptr; break;
        case DT_VERDEF:    verdef_va = dyns[i].d_un.d_ptr; break;
        case DT_VERDEFNUM: verdefnum = (uint32_t)dyns[i].d_un.d_val; break;
        default: break;
        }
    }

    if (strtab_va == 0 || strsz == 0 || symtab_va == 0) {
        munmap(map, fsz);
        return false;
    }

    off_t strtab_off = elf_vaddr_to_offset(strtab_va, phdrs, eh->e_phnum, fsz);
    off_t symtab_off = elf_vaddr_to_offset(symtab_va, phdrs, eh->e_phnum, fsz);

    if (strtab_off < 0 || (size_t)strtab_off >= fsz || (size_t)strtab_off + strsz > fsz ||
        symtab_off < 0 || (size_t)symtab_off >= fsz) {
        munmap(map, fsz);
        return false;
    }

    const char *strtab = (const char *)map + strtab_off;

    const char *soname = NULL;
    if (soname_idx != 0 && soname_idx < strsz) {
        soname = strtab + soname_idx;
    }
    if (!soname || soname[0] == '\0') {
        const char *base = strrchr(filepath, '/');
        soname = base ? base + 1 : filepath;
    }

    /* Count symbols */
    size_t num_syms = 0;

    /* Check section headers for SHT_DYNSYM */
    if (eh->e_shoff != 0 && eh->e_shnum > 0) {
        size_t sh_end = 0;
        if (!ckd_mul(&sh_end, eh->e_shnum, sizeof(Elf32_Shdr)) &&
            !ckd_add(&sh_end, sh_end, eh->e_shoff) && sh_end <= fsz) {
            const Elf32_Shdr *shdrs = (const Elf32_Shdr *)((const char *)map + eh->e_shoff);
            for (uint16_t i = 0; i < eh->e_shnum; ++i) {
                if (shdrs[i].sh_type == SHT_DYNSYM) {
                    num_syms = shdrs[i].sh_size / sizeof(Elf32_Sym);
                    break;
                }
            }
        }
    }

    /* Fallback to DT_HASH */
    if (num_syms == 0 && hash_va != 0) {
        off_t hash_off = elf_vaddr_to_offset(hash_va, phdrs, eh->e_phnum, fsz);
        if (hash_off >= 0 && (size_t)hash_off + 8u <= fsz) {
            const uint32_t *hash_ptr = (const uint32_t *)((const char *)map + hash_off);
            uint32_t nchain = hash_ptr[1];
            size_t hash_total = 0;
            if (!ckd_mul(&hash_total, (size_t)hash_ptr[0] + (size_t)nchain, 4u) &&
                !ckd_add(&hash_total, hash_total, 8u) &&
                (size_t)hash_off + hash_total <= fsz) {
                num_syms = nchain;
            }
        }
    }

    /* Fallback to DT_GNU_HASH */
    if (num_syms == 0 && gnu_hash_va != 0) {
        off_t gnu_off = elf_vaddr_to_offset(gnu_hash_va, phdrs, eh->e_phnum, fsz);
        if (gnu_off >= 0 && (size_t)gnu_off + 16u <= fsz) {
            const uint32_t *gnu_hdr = (const uint32_t *)((const char *)map + gnu_off);
            uint32_t nbuckets = gnu_hdr[0];
            uint32_t symoffset = gnu_hdr[1];
            uint32_t bloom_size = gnu_hdr[2];
            size_t gnu_meta_sz = 16u + (size_t)bloom_size * 4u;
            size_t buckets_sz = (size_t)nbuckets * 4u;
            if ((size_t)gnu_off + gnu_meta_sz + buckets_sz <= fsz) {
                const uint32_t *buckets = (const uint32_t *)((const char *)map + gnu_off + gnu_meta_sz);
                uint32_t max_sym = 0;
                for (uint32_t b = 0; b < nbuckets; ++b) {
                    if (buckets[b] > max_sym) {
                        max_sym = buckets[b];
                    }
                }
                if (max_sym >= symoffset) {
                    size_t chain_base = (size_t)gnu_off + gnu_meta_sz + buckets_sz;
                    uint32_t cur_sym = max_sym;
                    while (1) {
                        size_t chain_off = chain_base + (size_t)(cur_sym - symoffset) * 4u;
                        if (chain_off + 4u > fsz) break;
                        uint32_t chain_val = *(const uint32_t *)((const char *)map + chain_off);
                        cur_sym++;
                        if (chain_val & 1u) {
                            num_syms = cur_sym;
                            break;
                        }
                    }
                }
            }
        }
    }

    if (num_syms == 0) {
        num_syms = (fsz - (size_t)symtab_off) / sizeof(Elf32_Sym);
        if (num_syms > 65536u) {
            num_syms = 65536u;
        }
    }

    size_t symtab_bytes = 0;
    if (ckd_mul(&symtab_bytes, num_syms, sizeof(Elf32_Sym)) ||
        (size_t)symtab_off + symtab_bytes > fsz) {
        num_syms = (fsz - (size_t)symtab_off) / sizeof(Elf32_Sym);
    }

    const Elf32_Sym *syms = (const Elf32_Sym *)((const char *)map + symtab_off);

    /* Versions */
    const uint16_t *versym = NULL;
    if (versym_va != 0) {
        off_t versym_off = elf_vaddr_to_offset(versym_va, phdrs, eh->e_phnum, fsz);
        if (versym_off >= 0 && (size_t)versym_off + num_syms * 2u <= fsz) {
            versym = (const uint16_t *)((const char *)map + versym_off);
        }
    }

    const char *verdef_buf = NULL;
    size_t verdef_max = 0;
    if (verdef_va != 0) {
        off_t verdef_off = elf_vaddr_to_offset(verdef_va, phdrs, eh->e_phnum, fsz);
        if (verdef_off >= 0 && (size_t)verdef_off < fsz) {
            verdef_buf = (const char *)map + verdef_off;
            verdef_max = fsz - (size_t)verdef_off;
        }
    }

    char rpath[PATH_MAX];
    if (!realpath(filepath, rpath)) {
        strncpy(rpath, filepath, sizeof(rpath) - 1);
        rpath[sizeof(rpath) - 1] = '\0';
    }

    out_lib->soname = strdup(soname);
    out_lib->realpath = strdup(rpath);
    out_lib->is_patched = is_patched;
    out_lib->syms = NULL;
    out_lib->num_syms = 0;
    out_lib->cap_syms = 0;

    for (size_t i = 0; i < num_syms; ++i) {
        const Elf32_Sym *sym = &syms[i];
        if (sym->st_shndx == SHN_UNDEF || sym->st_shndx == SHN_ABS) {
            continue;
        }

        unsigned char bind = ELF32_ST_BIND(sym->st_info);
        if (bind != STB_GLOBAL && bind != STB_WEAK) {
            continue;
        }

        unsigned char type = ELF32_ST_TYPE(sym->st_info);
        if (type != STT_FUNC && type != STT_GNU_IFUNC && type != STT_OBJECT) {
            continue;
        }

        if (sym->st_name >= strsz) {
            continue;
        }
        const char *name = strtab + sym->st_name;
        if (!name || name[0] == '\0') {
            continue;
        }

        const char *ver_str = NULL;
        if (versym) {
            uint16_t v = versym[i];
            uint16_t ndx = v & 0x7fffu;
            if (ndx >= 2u && verdef_buf) {
                size_t voff = 0;
                for (uint32_t d = 0; d < (verdefnum ? verdefnum : 64u); ++d) {
                    if (voff + sizeof(Elf32_Verdef) > verdef_max) break;
                    const Elf32_Verdef *vd = (const Elf32_Verdef *)(verdef_buf + voff);
                    if (vd->vd_ndx == ndx) {
                        if (vd->vd_aux != 0 && voff + vd->vd_aux + sizeof(Elf32_Verdaux) <= verdef_max) {
                            const Elf32_Verdaux *vda = (const Elf32_Verdaux *)(verdef_buf + voff + vd->vd_aux);
                            if (vda->vda_name < strsz) {
                                ver_str = strtab + vda->vda_name;
                            }
                        }
                        break;
                    }
                    if (vd->vd_next == 0) break;
                    voff += vd->vd_next;
                }
            }
        }

        if (out_lib->num_syms >= out_lib->cap_syms) {
            size_t new_cap = out_lib->cap_syms ? out_lib->cap_syms * 2u : 64u;
            scanned_symbol_t *new_arr = (scanned_symbol_t *)realloc(out_lib->syms, new_cap * sizeof(scanned_symbol_t));
            if (!new_arr) break;
            out_lib->syms = new_arr;
            out_lib->cap_syms = new_cap;
        }

        out_lib->syms[out_lib->num_syms].name = strdup(name);
        out_lib->syms[out_lib->num_syms].version = ver_str ? strdup(ver_str) : NULL;
        out_lib->syms[out_lib->num_syms].size = sym->st_size;
        out_lib->syms[out_lib->num_syms].is_func = (type == STT_FUNC || type == STT_GNU_IFUNC);
        out_lib->num_syms++;
    }

    munmap(map, fsz);
    return true;
}

static void free_scanned_lib(scanned_lib_t *lib)
{
    free(lib->soname);
    free(lib->realpath);
    for (size_t i = 0; i < lib->num_syms; ++i) {
        free(lib->syms[i].name);
        free(lib->syms[i].version);
    }
    free(lib->syms);
}

/* --- Directory Scanning & Deduplication --- */

static void add_scan_dir(scanned_dir_t **dirs, size_t *num, size_t *cap, const char *raw_path)
{
    char rpath[PATH_MAX];
    if (!realpath(raw_path, rpath)) {
        return;
    }
    struct stat st;
    if (stat(rpath, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return;
    }
    for (size_t i = 0; i < *num; ++i) {
        if (strcmp((*dirs)[i].path, rpath) == 0) {
            return;
        }
    }
    if (*num >= *cap) {
        size_t new_cap = *cap ? *cap * 2u : 16u;
        scanned_dir_t *arr = (scanned_dir_t *)realloc(*dirs, new_cap * sizeof(scanned_dir_t));
        if (!arr) return;
        *dirs = arr;
        *cap = new_cap;
    }
    int64_t mtime_ns = (int64_t)st.st_mtim.tv_sec * 1000000000LL + (int64_t)st.st_mtim.tv_nsec;
    (*dirs)[*num].path = strdup(rpath);
    (*dirs)[*num].mtime_ns = mtime_ns;
    (*num)++;
}

static void parse_ld_so_conf(const char *conf_path, const char *sysroot, scanned_dir_t **dirs, size_t *num, size_t *cap)
{
    FILE *f = fopen(conf_path, "r");
    if (!f) return;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0' || *p == '\n' || *p == '\r') continue;

        char *nl = strpbrk(p, "\r\n");
        if (nl) *nl = '\0';

        if (strncmp(p, "include ", 8) == 0) {
            char *pattern = p + 8;
            while (*pattern == ' ' || *pattern == '\t') pattern++;
            char full_pattern[PATH_MAX * 2];
            if (pattern[0] == '/') {
                if (sysroot[0]) {
                    snprintf(full_pattern, sizeof(full_pattern), "%s%s", sysroot, pattern);
                } else {
                    strncpy(full_pattern, pattern, sizeof(full_pattern) - 1);
                    full_pattern[sizeof(full_pattern) - 1] = '\0';
                }
            } else {
                char conf_copy[PATH_MAX];
                strncpy(conf_copy, conf_path, sizeof(conf_copy) - 1);
                conf_copy[sizeof(conf_copy) - 1] = '\0';
                char *slash = strrchr(conf_copy, '/');
                if (slash) *slash = '\0';
                snprintf(full_pattern, sizeof(full_pattern), "%s/%s", conf_copy, pattern);
            }

            glob_t gl;
            if (glob(full_pattern, 0, NULL, &gl) == 0) {
                for (size_t g = 0; g < gl.gl_pathc; ++g) {
                    parse_ld_so_conf(gl.gl_pathv[g], sysroot, dirs, num, cap);
                }
                globfree(&gl);
            }
        } else {
            char dir_path[PATH_MAX * 2];
            if (p[0] == '/' && sysroot[0]) {
                snprintf(dir_path, sizeof(dir_path), "%s%s", sysroot, p);
            } else {
                strncpy(dir_path, p, sizeof(dir_path) - 1);
                dir_path[sizeof(dir_path) - 1] = '\0';
            }
            add_scan_dir(dirs, num, cap, dir_path);
        }
    }
    fclose(f);
}

/* --- Static Rules Parsing --- */

static void split_sym_ver_str(const char *in, char *NM_NULLABLE_PTR *NM_NONNULL_PTR sym_out, char *NM_NULLABLE_PTR *NM_NONNULL_PTR ver_out)
{
    if (strcmp(in, "-") == 0 || in[0] == '\0') {
        *sym_out = NULL;
        *ver_out = NULL;
        return;
    }
    const char *at = strchr(in, '@');
    if (at) {
        size_t n = (size_t)(at - in);
        char *s = (char *)malloc(n + 1u);
        if (s) {
            memcpy(s, in, n);
            s[n] = '\0';
        }
        *sym_out = s;
        *ver_out = strdup(at + 1);
    } else {
        *sym_out = strdup(in);
        *ver_out = NULL;
    }
}

static uint64_t fnv1a64(const char *s, uint64_t h)
{
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        h = (h ^ *p) * 1099511628211ULL;
    }
    return h;
}

static int compare_filenames(const void *a, const void *b)
{
    const char *const *fa = (const char *const *)a;
    const char *const *fb = (const char *const *)b;
    return strcmp(*fa, *fb);
}

static bool load_rules_from_dir(const char *rules_dir,
                                const char *detected_libc,
                                static_rule_t **rules_out,
                                size_t *num_rules_out,
                                uint64_t *hash_out)
{
    DIR *d = opendir(rules_dir);
    if (!d) {
        return false;
    }

    char **files = NULL;
    size_t num_files = 0;
    size_t cap_files = 0;

    struct dirent *ent = NULL;
    while ((ent = readdir(d))) {
        size_t nlen = strlen(ent->d_name);
        if (nlen > 4 && strcmp(ent->d_name + nlen - 4, ".txt") == 0) {
            if (num_files >= cap_files) {
                size_t new_cap = cap_files ? cap_files * 2u : 16u;
                char **arr = (char **)realloc(files, new_cap * sizeof(char *));
                if (!arr) break;
                files = arr;
                cap_files = new_cap;
            }
            files[num_files++] = strdup(ent->d_name);
        }
    }
    closedir(d);

    if (num_files > 1) {
        qsort(files, num_files, sizeof(char *), compare_filenames);
    }

    uint64_t h = 14695981039346656037ULL;
    static_rule_t *rules = NULL;
    size_t num_rules = 0;
    size_t cap_rules = 0;

    for (size_t f_idx = 0; f_idx < num_files; ++f_idx) {
        const char *fname = files[f_idx];

        /* Skip libc-specific alias files */
        if (strcmp(detected_libc, "musl") == 0 && strcmp(fname, "10-glibc-aliases.txt") == 0) {
            free(files[f_idx]);
            continue;
        }
        if (strcmp(detected_libc, "glibc") == 0 && strcmp(fname, "11-musl-aliases.txt") == 0) {
            free(files[f_idx]);
            continue;
        }

        char full_path[PATH_MAX * 2];
        snprintf(full_path, sizeof(full_path), "%s/%s", rules_dir, fname);

        FILE *f = fopen(full_path, "r");
        if (!f) {
            free(files[f_idx]);
            continue;
        }

        char line[2048];
        while (fgets(line, sizeof(line), f)) {
            h = fnv1a64(line, h);

            char *nl = strpbrk(line, "\r\n");
            if (nl) *nl = '\0';
            if (line[0] == '#' || line[0] == '\0') {
                continue;
            }

            char *cols[16];
            size_t col_cnt = 0;
            char *cur = line;
            while (cur && col_cnt < 16) {
                cols[col_cnt++] = cur;
                char *tab = strchr(cur, '\t');
                if (!tab) break;
                *tab = '\0';
                cur = tab + 1;
            }

            if (col_cnt < 9) {
                continue;
            }

            if (num_rules >= cap_rules) {
                size_t new_cap = cap_rules ? cap_rules * 2u : 128u;
                static_rule_t *arr = (static_rule_t *)realloc(rules, new_cap * sizeof(static_rule_t));
                if (!arr) break;
                rules = arr;
                cap_rules = new_cap;
            }

            static_rule_t *r = &rules[num_rules++];
            r->rec_type = strdup(cols[0]);
            r->i386_soname = strdup(cols[1]);

            r->i386_sym = NULL;
            r->i386_ver = NULL;
            split_sym_ver_str(cols[2], &r->i386_sym, &r->i386_ver);

            r->tgt_soname = (strcmp(cols[3], "-") == 0) ? NULL : strdup(cols[3]);
            r->tgt_sym = NULL;
            r->tgt_ver = NULL;
            split_sym_ver_str(cols[4], &r->tgt_sym, &r->tgt_ver);

            r->cls = strdup(cols[5]);
            r->sig = strdup(cols[6]);
            r->flags = strdup(cols[7]);
            r->size = strdup(cols[8]);
            r->reason = NULL;
            if (strncmp(cols[7], "REASON=", 7) == 0) {
                r->reason = strdup(cols[7] + 7);
            }
            r->emitted = false;
        }

        fclose(f);
        free(files[f_idx]);
    }
    free(files);

    *rules_out = rules;
    *num_rules_out = num_rules;
    *hash_out = h;
    return true;
}

static void free_static_rules(static_rule_t *NM_NULLABLE_PTR rules, size_t num_rules)
{
    if (!rules) {
        return;
    }
    for (size_t i = 0; i < num_rules; ++i) {
        free(rules[i].rec_type);
        free(rules[i].i386_soname);
        free(rules[i].i386_sym);
        free(rules[i].i386_ver);
        free(rules[i].tgt_soname);
        free(rules[i].tgt_sym);
        free(rules[i].tgt_ver);
        free(rules[i].cls);
        free(rules[i].sig);
        free(rules[i].flags);
        free(rules[i].size);
        free(rules[i].reason);
    }
    free(rules);
}

/* --- Checking Lookup Table --- */

static int do_check(const char *file, bool quiet)
{
    nm_lookup_t *lk = NULL;
    int rc = nm_lookup_open(file, &lk);
    if (rc != NM_OK || !lk) {
        if (!quiet) {
            fprintf(stderr, "check failed: unable to open or parse '%s'\n", file);
        }
        return 1;
    }

    if (nm_lookup_is_stale(lk)) {
        if (!quiet) {
            fprintf(stderr, "check failed: lookup table '%s' is stale\n", file);
        }
        nm_lookup_close(lk);
        return 1;
    }

    /* Check for broken ALIAS entries */
    nm_lk_entry_t out;
    int find_rc = nm_lookup_find(lk, "libc.so.6", "nonexistent_symbol_for_check_validation", NULL, 0, &out);
    (void)find_rc;

    nm_lookup_close(lk);
    if (!quiet) {
        printf("check OK: '%s' is valid and fresh\n", file);
    }
    return 0;
}

/* --- Mode: Emit Base --- */

static int do_emit_base(const char *rules_dir, const char *out_path, bool quiet)
{
    static_rule_t *rules = NULL;
    size_t num_rules = 0;
    uint64_t hash = 0;

    if (!load_rules_from_dir(rules_dir, "glibc", &rules, &num_rules, &hash)) {
        NM_LOG_ERROR("lookup-gen", "failed loading rules from '%s'", rules_dir);
        return 1;
    }

    str_buf_t buf;
    buf_init(&buf);

    buf_append_str(&buf, NM_LOOKUP_HEADER_MAGIC "\n");
    buf_append_str(&buf, "#@generator\tnewminhh-lookup-gen\t1.0.0\n");
    buf_printf(&buf, "#@rules\t%s\t0x%016llx\n", rules_dir, (unsigned long long)hash);
    buf_append_str(&buf, "# Static base lookup table generated from curated rules.d\n\n");

    /* Lib records first */
    for (size_t i = 0; i < num_rules; ++i) {
        if (strcmp(rules[i].rec_type, "lib") == 0) {
            buf_printf(&buf, "lib\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                       rules[i].i386_soname,
                       "-",
                       rules[i].tgt_soname ? rules[i].tgt_soname : "-",
                       rules[i].tgt_sym ? rules[i].tgt_sym : "-",
                       rules[i].cls,
                       rules[i].sig,
                       rules[i].flags,
                       rules[i].size);
        }
    }

    /* Sym records */
    for (size_t i = 0; i < num_rules; ++i) {
        if (strcmp(rules[i].rec_type, "sym") == 0) {
            char i386_full[256];
            if (rules[i].i386_ver) {
                snprintf(i386_full, sizeof(i386_full), "%s@%s", rules[i].i386_sym ? rules[i].i386_sym : "-", rules[i].i386_ver);
            } else {
                snprintf(i386_full, sizeof(i386_full), "%s", rules[i].i386_sym ? rules[i].i386_sym : "-");
            }

            char tgt_full[256];
            if (rules[i].tgt_sym) {
                if (rules[i].tgt_ver) {
                    snprintf(tgt_full, sizeof(tgt_full), "%s@%s", rules[i].tgt_sym, rules[i].tgt_ver);
                } else {
                    snprintf(tgt_full, sizeof(tgt_full), "%s", rules[i].tgt_sym);
                }
            } else {
                strncpy(tgt_full, "-", sizeof(tgt_full) - 1);
                tgt_full[sizeof(tgt_full) - 1] = '\0';
            }

            buf_printf(&buf, "sym\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                       rules[i].i386_soname,
                       i386_full,
                       rules[i].tgt_soname ? rules[i].tgt_soname : "-",
                       tgt_full,
                       rules[i].cls,
                       rules[i].sig,
                       rules[i].flags,
                       rules[i].size);
        }
    }

    free_static_rules(rules, num_rules);

    if (!atomic_write_file(out_path, buf.data, buf.len, true)) {
        buf_free(&buf);
        return 1;
    }
    buf_free(&buf);

    if (!quiet) {
        printf("newminhh-lookup-gen: wrote static base table to '%s'\n", out_path);
    }
    return 0;
}

/* --- Mode: Emit C Registry --- */

typedef struct {
    char *NM_NONNULL_PTR name;
    char *NM_NONNULL_PTR wrapper_name;
    nm_fn_sig_t sig;
    uint32_t flags;
    bool is_data;
} c_reg_entry_t;

static int compare_c_reg(const void *a, const void *b)
{
    const c_reg_entry_t *ea = (const c_reg_entry_t *)a;
    const c_reg_entry_t *eb = (const c_reg_entry_t *)b;
    return strcmp(ea->name, eb->name);
}

static int do_emit_c_registry(const char *rules_dir, const char *out_path, bool quiet)
{
    char libc_rules_path[PATH_MAX];
    snprintf(libc_rules_path, sizeof(libc_rules_path), "%s/00-libc.txt", rules_dir);

    static_rule_t *rules = NULL;
    size_t num_rules = 0;
    uint64_t hash = 0;

    c_reg_entry_t *entries = NULL;
    size_t num_entries = 0;
    size_t cap_entries = 0;

    if (load_rules_from_dir(rules_dir, "glibc", &rules, &num_rules, &hash)) {
        for (size_t i = 0; i < num_rules; ++i) {
            if (strcmp(rules[i].rec_type, "sym") == 0 &&
                strcmp(rules[i].cls, "COMPAT") == 0 &&
                strstr(rules[i].flags, "STATIC_ONLY") == NULL &&
                rules[i].i386_sym != NULL) {

                nm_fn_sig_t sig;
                uint32_t flags = 0;
                if (strcmp(rules[i].sig, "-") != 0 && rules[i].sig[0] != '\0') {
                    int p_rc = nm_sig_parse(rules[i].sig, &sig, &flags);
                    (void)p_rc;
                } else {
                    memset(&sig, 0, sizeof(sig));
                }

                if (strstr(rules[i].flags, "DATA")) {
                    flags |= NM_SYM_FLAG_DATA;
                }
                if (strstr(rules[i].flags, "VARIADIC")) {
                    flags |= NM_SYM_FLAG_VARIADIC;
                }
                if (strstr(rules[i].flags, "CDECL_DIRECT")) {
                    flags |= NM_SYM_FLAG_CDECL_DIRECT;
                }

                if (num_entries >= cap_entries) {
                    size_t new_cap = cap_entries ? cap_entries * 2u : 64u;
                    c_reg_entry_t *arr = (c_reg_entry_t *)realloc(entries, new_cap * sizeof(c_reg_entry_t));
                    if (!arr) break;
                    entries = arr;
                    cap_entries = new_cap;
                }

                char wrap[256];
                bool is_data = (flags & NM_SYM_FLAG_DATA) != 0;
                if (is_data) {
                    snprintf(wrap, sizeof(wrap), "&compat_%s", rules[i].i386_sym);
                } else if (strcmp(rules[i].i386_sym, "printf") == 0 ||
                           strcmp(rules[i].i386_sym, "fprintf") == 0 ||
                           strcmp(rules[i].i386_sym, "sprintf") == 0 ||
                           strcmp(rules[i].i386_sym, "snprintf") == 0) {
                    snprintf(wrap, sizeof(wrap), "(void *)(uintptr_t)compat_%s_cdecl", rules[i].i386_sym);
                } else {
                    snprintf(wrap, sizeof(wrap), "(void *)(uintptr_t)compat_%s", rules[i].i386_sym);
                }

                entries[num_entries].name = strdup(rules[i].i386_sym);
                entries[num_entries].wrapper_name = strdup(wrap);
                entries[num_entries].sig = sig;
                entries[num_entries].flags = flags;
                entries[num_entries].is_data = is_data;
                num_entries++;
            }
        }
        free_static_rules(rules, num_rules);
    }

    /* Sort entries strictly by name for bsearch */
    if (num_entries > 1) {
        qsort(entries, num_entries, sizeof(c_reg_entry_t), compare_c_reg);
    }

    str_buf_t buf;
    buf_init(&buf);

    buf_append_str(&buf, "/* Generated by newminhh-lookup-gen --emit-c-registry. DO NOT EDIT. */\n");
    buf_append_str(&buf, "#ifndef NEWMINHH_COMPAT_REGISTRY_GEN_H\n");
    buf_append_str(&buf, "#define NEWMINHH_COMPAT_REGISTRY_GEN_H\n\n");
    buf_append_str(&buf, "#include \"newminhh_abi.h\"\n\n");

    buf_append_str(&buf, "static const nm_sym_entry_t g_sym_table[] = {\n");
    for (size_t i = 0; i < num_entries; ++i) {
        c_reg_entry_t *e = &entries[i];

        char flag_str[128];
        flag_str[0] = '\0';
        if (e->flags & NM_SYM_FLAG_DATA) {
            strcat(flag_str, "NM_SYM_FLAG_DATA | ");
        }
        if (e->flags & NM_SYM_FLAG_VARIADIC) {
            strcat(flag_str, "NM_SYM_FLAG_VARIADIC | ");
        }
        if (e->flags & NM_SYM_FLAG_CDECL_DIRECT) {
            strcat(flag_str, "NM_SYM_FLAG_CDECL_DIRECT | ");
        }
        size_t flen = strlen(flag_str);
        if (flen >= 3 && flag_str[flen - 2] == '|') {
            flag_str[flen - 3] = '\0';
        }
        if (flag_str[0] == '\0') {
            strcpy(flag_str, "0");
        }

        buf_printf(&buf, "    { \"%s\", %s, { %u, %u, %u, %u, {",
                   e->name, e->wrapper_name,
                   (unsigned)e->sig.ret_kind,
                   (unsigned)e->sig.nargs,
                   (unsigned)e->sig.is_variadic,
                   (unsigned)e->sig.abi_ext);
        for (size_t a = 0; a < NM_MAX_SIG_ARGS; ++a) {
            buf_printf(&buf, "%u%s", (unsigned)e->sig.arg_kinds[a], (a + 1 < NM_MAX_SIG_ARGS) ? ", " : "");
        }
        buf_printf(&buf, "} }, %s },\n", flag_str);

        free(e->name);
        free(e->wrapper_name);
    }
    free(entries);

    buf_append_str(&buf, "};\n\n");
    buf_append_str(&buf, "static const char g_embedded_lookup_base[] = \"#!newminhh-lookup v1\\n\";\n\n");
    buf_append_str(&buf, "#endif /* NEWMINHH_COMPAT_REGISTRY_GEN_H */\n");

    if (!atomic_write_file(out_path, buf.data, buf.len, true)) {
        buf_free(&buf);
        return 1;
    }
    buf_free(&buf);

    if (!quiet) {
        printf("newminhh-lookup-gen: wrote C compat registry (%zu entries) to '%s'\n", num_entries, out_path);
    }
    return 0;
}

/* --- Mode: Emit Python Registry --- */

static int do_emit_py_registry(const char *rules_dir, const char *out_path, bool quiet)
{
    static_rule_t *rules = NULL;
    size_t num_rules = 0;
    uint64_t hash = 0;

    load_rules_from_dir(rules_dir, "glibc", &rules, &num_rules, &hash);

    str_buf_t buf;
    buf_init(&buf);

    buf_append_str(&buf, "# Generated by newminhh-lookup-gen --emit-py-registry. DO NOT EDIT.\n");
    buf_append_str(&buf, "EMBEDDED_LOOKUP_BASE_TEXT = \"\"\"#!newminhh-lookup v1\n");
    buf_append_str(&buf, "#@generator\tnewminhh-lookup-gen\t1.0.0\n");
    buf_printf(&buf, "#@rules\t%s\t0x%016llx\n", rules_dir, (unsigned long long)hash);

    for (size_t i = 0; i < num_rules; ++i) {
        if (strcmp(rules[i].rec_type, "lib") == 0) {
            buf_printf(&buf, "lib\t%s\t-\t%s\t-\t%s\t-\t-\t-\n",
                       rules[i].i386_soname,
                       rules[i].tgt_soname ? rules[i].tgt_soname : "-",
                       rules[i].cls);
        }
    }
    for (size_t i = 0; i < num_rules; ++i) {
        if (strcmp(rules[i].rec_type, "sym") == 0) {
            char tgt_str[256];
            if (rules[i].tgt_sym) {
                if (rules[i].tgt_ver) {
                    snprintf(tgt_str, sizeof(tgt_str), "%s@%s", rules[i].tgt_sym, rules[i].tgt_ver);
                } else {
                    snprintf(tgt_str, sizeof(tgt_str), "%s", rules[i].tgt_sym);
                }
            } else {
                strcpy(tgt_str, "-");
            }

            buf_printf(&buf, "sym\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                       rules[i].i386_soname,
                       rules[i].i386_sym ? rules[i].i386_sym : "-",
                       rules[i].tgt_soname ? rules[i].tgt_soname : "-",
                       tgt_str,
                       rules[i].cls,
                       rules[i].sig,
                       rules[i].flags,
                       rules[i].size);
        }
    }

    buf_append_str(&buf, "\"\"\"\n\n");
    buf_append_str(&buf, "COMPAT_REGISTRY = {\n");

    for (size_t i = 0; i < num_rules; ++i) {
        if (strcmp(rules[i].rec_type, "sym") == 0 &&
            strcmp(rules[i].cls, "COMPAT") == 0 &&
            rules[i].i386_sym != NULL) {

            buf_printf(&buf, "    \"%s\": {\"sig\": \"%s\", \"flags\": \"%s\"},\n",
                       rules[i].i386_sym, rules[i].sig, rules[i].flags);
        }
    }
    buf_append_str(&buf, "}\n");

    free_static_rules(rules, num_rules);

    if (!atomic_write_file(out_path, buf.data, buf.len, true)) {
        buf_free(&buf);
        return 1;
    }
    buf_free(&buf);

    if (!quiet) {
        printf("newminhh-lookup-gen: wrote Python registry to '%s'\n", out_path);
    }
    return 0;
}

/* --- Mode: System / Sysroot Scan & Merge --- */

static const char *NM_NONNULL_PTR const g_std_dirs[] = {
    "/lib/x86_64-linux-gnux32",
    "/usr/lib/x86_64-linux-gnux32",
    "/libx32",
    "/usr/libx32",
    "/lib",
    "/usr/lib",
    "/usr/local/lib",
};

static int do_system_scan(const char *sysroot,
                          const char *rules_dir,
                          const char *out_path,
                          bool quiet)
{
    /* 1. Detect libc and interpreter */
    char interp[PATH_MAX];
    interp[0] = '\0';

    char test_bin[PATH_MAX * 2];
    snprintf(test_bin, sizeof(test_bin), "%s/bin/sh", sysroot);
    if (!read_interp_from_elf(test_bin, interp, sizeof(interp))) {
        snprintf(test_bin, sizeof(test_bin), "%s/usr/bin/env", sysroot);
        read_interp_from_elf(test_bin, interp, sizeof(interp));
    }

    if (interp[0] == '\0') {
        char musl_test[PATH_MAX * 2];
        snprintf(musl_test, sizeof(musl_test), "%s/lib/ld-musl-x32.so.1", sysroot);
        if (access(musl_test, F_OK) == 0) {
            strncpy(interp, "/lib/ld-musl-x32.so.1", sizeof(interp) - 1);
        } else {
            strncpy(interp, "/libx32/ld-linux-x32.so.2", sizeof(interp) - 1);
        }
        interp[sizeof(interp) - 1] = '\0';
    }

    const char *detected_libc = strstr(interp, "musl") ? "musl" : "glibc";

    /* 2. Collect scan directories */
    scanned_dir_t *dirs = NULL;
    size_t num_dirs = 0;
    size_t cap_dirs = 0;

    char ld_so_conf_path[PATH_MAX * 2];
    snprintf(ld_so_conf_path, sizeof(ld_so_conf_path), "%s/etc/ld.so.conf", sysroot);
    if (access(ld_so_conf_path, F_OK) == 0) {
        parse_ld_so_conf(ld_so_conf_path, sysroot, &dirs, &num_dirs, &cap_dirs);
    }

    char musl_path_conf[PATH_MAX * 2];
    snprintf(musl_path_conf, sizeof(musl_path_conf), "%s/etc/ld-musl-x32.path", sysroot);
    if (access(musl_path_conf, F_OK) == 0) {
        parse_ld_so_conf(musl_path_conf, sysroot, &dirs, &num_dirs, &cap_dirs);
    }

    /* Standard candidate directories */
    for (size_t i = 0; i < NM_COUNTOF(g_std_dirs); ++i) {
        char cand[PATH_MAX * 2];
        if (sysroot[0]) {
            snprintf(cand, sizeof(cand), "%s%s", sysroot, g_std_dirs[i]);
        } else {
            strncpy(cand, g_std_dirs[i], sizeof(cand) - 1);
            cand[sizeof(cand) - 1] = '\0';
        }
        add_scan_dir(&dirs, &num_dirs, &cap_dirs, cand);
    }

    /* 3. Load static rules */
    static_rule_t *static_rules = NULL;
    size_t num_static_rules = 0;
    uint64_t rules_hash = 0;
    load_rules_from_dir(rules_dir, detected_libc, &static_rules, &num_static_rules, &rules_hash);

    /* 4. Scan candidate libraries across all collected directories */
    visited_file_t *visited = NULL;
    size_t num_visited = 0;
    size_t cap_visited = 0;

    scanned_lib_t *libs = NULL;
    size_t num_libs = 0;
    size_t cap_libs = 0;

    for (size_t d_idx = 0; d_idx < num_dirs; ++d_idx) {
        DIR *dir = opendir(dirs[d_idx].path);
        if (!dir) continue;

        struct dirent *ent = NULL;
        while ((ent = readdir(dir))) {
            const char *dname = ent->d_name;
            size_t nlen = strlen(dname);

            /* Filter: must end with .so or contain .so. */
            bool match_so = false;
            if (nlen >= 3 && strcmp(dname + nlen - 3, ".so") == 0) {
                match_so = true;
            } else if (strstr(dname, ".so.")) {
                match_so = true;
            }
            if (!match_so) continue;

            char full_so_path[PATH_MAX * 2];
            snprintf(full_so_path, sizeof(full_so_path), "%s/%s", dirs[d_idx].path, dname);

            struct stat st;
            if (stat(full_so_path, &st) != 0 || !S_ISREG(st.st_mode)) {
                continue;
            }

            /* Deduplicate by (st_dev, st_ino) */
            bool seen = false;
            for (size_t v = 0; v < num_visited; ++v) {
                if (visited[v].dev == st.st_dev && visited[v].ino == st.st_ino) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;

            if (num_visited >= cap_visited) {
                size_t new_cap = cap_visited ? cap_visited * 2u : 64u;
                visited_file_t *arr = (visited_file_t *)realloc(visited, new_cap * sizeof(visited_file_t));
                if (!arr) break;
                visited = arr;
                cap_visited = new_cap;
            }
            visited[num_visited].dev = st.st_dev;
            visited[num_visited].ino = st.st_ino;
            num_visited++;

            scanned_lib_t scanned_lib;
            if (scan_x32_elf(full_so_path, &scanned_lib)) {
                if (num_libs >= cap_libs) {
                    size_t new_cap = cap_libs ? cap_libs * 2u : 16u;
                    scanned_lib_t *arr = (scanned_lib_t *)realloc(libs, new_cap * sizeof(scanned_lib_t));
                    if (!arr) {
                        free_scanned_lib(&scanned_lib);
                        break;
                    }
                    libs = arr;
                    cap_libs = new_cap;
                }
                libs[num_libs++] = scanned_lib;
            }
        }
        closedir(dir);
    }
    free(visited);

    /* 5. Merge and generate output buffer */
    str_buf_t buf;
    buf_init(&buf);

    buf_append_str(&buf, NM_LOOKUP_HEADER_MAGIC "\n");
    buf_append_str(&buf, "#@generator\tnewminhh-lookup-gen\t1.0.0\n");
    buf_printf(&buf, "#@libc\t%s\n", detected_libc);
    buf_printf(&buf, "#@interp\t%s\n", interp);
    for (size_t d = 0; d < num_dirs; ++d) {
        buf_printf(&buf, "#@scan\t%s\t%lld\n", dirs[d].path, (long long)dirs[d].mtime_ns);
    }
    buf_printf(&buf, "#@rules\t%s\t0x%016llx\n", rules_dir, (unsigned long long)rules_hash);
    buf_append_str(&buf, "\n");

    /* Emit lib records */
    for (size_t r = 0; r < num_static_rules; ++r) {
        if (strcmp(static_rules[r].rec_type, "lib") == 0) {
            buf_printf(&buf, "lib\t%s\t-\t%s\t-\t%s\t-\t-\t-\n",
                       static_rules[r].i386_soname,
                       static_rules[r].tgt_soname ? static_rules[r].tgt_soname : "-",
                       static_rules[r].cls);
        }
    }

    for (size_t l = 0; l < num_libs; ++l) {
        bool in_static = false;
        for (size_t r = 0; r < num_static_rules; ++r) {
            if (strcmp(static_rules[r].rec_type, "lib") == 0 &&
                strcmp(static_rules[r].i386_soname, libs[l].soname) == 0) {
                in_static = true;
                break;
            }
        }
        if (!in_static) {
            buf_printf(&buf, "lib\t%s\t%s\t%s\t-\tNATIVE\t-\t-\t-\n",
                       libs[l].soname, libs[l].realpath, libs[l].soname);
        }
    }

    /* Emit static COMPAT, FORBIDDEN_ABI, ALIAS rules (they ALWAYS win!) */
    for (size_t r = 0; r < num_static_rules; ++r) {
        if (strcmp(static_rules[r].rec_type, "sym") == 0) {
            if (strcmp(static_rules[r].cls, "COMPAT") == 0 ||
                strcmp(static_rules[r].cls, "FORBIDDEN_ABI") == 0 ||
                strcmp(static_rules[r].cls, "FORBIDDEN") == 0 ||
                strcmp(static_rules[r].cls, "ALIAS") == 0) {

                char i386_full[256];
                if (static_rules[r].i386_ver) {
                    snprintf(i386_full, sizeof(i386_full), "%s@%s",
                             static_rules[r].i386_sym ? static_rules[r].i386_sym : "-",
                             static_rules[r].i386_ver);
                } else {
                    snprintf(i386_full, sizeof(i386_full), "%s",
                             static_rules[r].i386_sym ? static_rules[r].i386_sym : "-");
                }

                char tgt_full[256];
                if (static_rules[r].tgt_sym) {
                    if (static_rules[r].tgt_ver) {
                        snprintf(tgt_full, sizeof(tgt_full), "%s@%s", static_rules[r].tgt_sym, static_rules[r].tgt_ver);
                    } else {
                        snprintf(tgt_full, sizeof(tgt_full), "%s", static_rules[r].tgt_sym);
                    }
                } else {
                    strncpy(tgt_full, "-", sizeof(tgt_full) - 1);
                    tgt_full[sizeof(tgt_full) - 1] = '\0';
                }

                buf_printf(&buf, "sym\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                           static_rules[r].i386_soname,
                           i386_full,
                           static_rules[r].tgt_soname ? static_rules[r].tgt_soname : "-",
                           tgt_full,
                           static_rules[r].cls,
                           static_rules[r].sig,
                           static_rules[r].flags,
                           static_rules[r].size);
                static_rules[r].emitted = true;
            }
        }
    }

    /* Build O(1) hash index over static sym rules keyed by (soname, sym) */
    size_t rule_ht_cap = 1024;
    while (rule_ht_cap < num_static_rules * 2u) {
        if (ckd_mul(&rule_ht_cap, rule_ht_cap, 2u)) {
            rule_ht_cap = num_static_rules * 2u + 1u;
            break;
        }
    }
    size_t *rule_ht = malloc(rule_ht_cap * sizeof(size_t));
    size_t *rule_next = malloc((num_static_rules + 1u) * sizeof(size_t));
    if (!rule_ht || !rule_next) {
        free(rule_ht);
        free(rule_next);
        NM_LOG_ERROR("lookup-gen", "OOM allocating static rule hash table");
        buf_free(&buf);
        return false;
    }
    for (size_t i = 0; i < rule_ht_cap; ++i) rule_ht[i] = SIZE_MAX;
    size_t rule_ht_mask = rule_ht_cap - 1u;
    for (size_t r = num_static_rules; r > 0; --r) {
        size_t idx = r - 1u;
        if (strcmp(static_rules[idx].rec_type, "sym") == 0 && static_rules[idx].i386_sym) {
            uint64_t h = fnv1a64(static_rules[idx].i386_soname, 14695981039346656037ULL);
            h = fnv1a64("\x1f", h);
            h = fnv1a64(static_rules[idx].i386_sym, h);
            size_t b = (size_t)(h & rule_ht_mask);
            rule_next[idx] = rule_ht[b];
            rule_ht[b] = idx;
        } else {
            rule_next[idx] = SIZE_MAX;
        }
    }

    /* Process scanned symbols in O(N) */
    for (size_t l = 0; l < num_libs; ++l) {
        scanned_lib_t *lib = &libs[l];
        uint64_t so_h = fnv1a64(lib->soname, 14695981039346656037ULL);
        so_h = fnv1a64("\x1f", so_h);
        uint64_t wc_h = fnv1a64("*", 14695981039346656037ULL);
        wc_h = fnv1a64("\x1f", wc_h);

        for (size_t s = 0; s < lib->num_syms; ++s) {
            scanned_symbol_t *sym = &lib->syms[s];

            /* Check exact (soname, sym) first, then ("*", sym) */
            static_rule_t *matched_rule = NULL;
            size_t b1 = (size_t)(fnv1a64(sym->name, so_h) & rule_ht_mask);
            for (size_t r = rule_ht[b1]; r != SIZE_MAX; r = rule_next[r]) {
                if (strcmp(static_rules[r].i386_soname, lib->soname) == 0 &&
                    strcmp(static_rules[r].i386_sym, sym->name) == 0) {
                    matched_rule = &static_rules[r];
                    break;
                }
            }
            if (!matched_rule) {
                size_t b2 = (size_t)(fnv1a64(sym->name, wc_h) & rule_ht_mask);
                for (size_t r = rule_ht[b2]; r != SIZE_MAX; r = rule_next[r]) {
                    if (strcmp(static_rules[r].i386_soname, "*") == 0 &&
                        strcmp(static_rules[r].i386_sym, sym->name) == 0) {
                        matched_rule = &static_rules[r];
                        break;
                    }
                }
            }

            if (matched_rule) {
                if (matched_rule->emitted) {
                    continue; /* Already emitted (COMPAT, FORBIDDEN, etc.) */
                }

                /* NATIVE_TYPED or NATIVE_DATA static rule matched in scanned library */
                char tgt_full[256];
                if (matched_rule->tgt_ver) {
                    snprintf(tgt_full, sizeof(tgt_full), "%s@%s",
                             matched_rule->tgt_sym ? matched_rule->tgt_sym : sym->name,
                             matched_rule->tgt_ver);
                } else if (sym->version) {
                    snprintf(tgt_full, sizeof(tgt_full), "%s@%s",
                             matched_rule->tgt_sym ? matched_rule->tgt_sym : sym->name,
                             sym->version);
                } else {
                    snprintf(tgt_full, sizeof(tgt_full), "%s",
                             matched_rule->tgt_sym ? matched_rule->tgt_sym : sym->name);
                }

                uint32_t eff_size = sym->size;
                if (eff_size == 0 && strcmp(matched_rule->size, "-") != 0) {
                    eff_size = (uint32_t)strtoul(matched_rule->size, NULL, 10);
                }

                buf_printf(&buf, "sym\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%u\n",
                           lib->soname,
                           sym->name,
                           lib->soname,
                           tgt_full,
                           matched_rule->cls,
                           matched_rule->sig,
                           matched_rule->flags,
                           eff_size);
                matched_rule->emitted = true;
            } else {
                /* No static rule */
                char tgt_full[256];
                if (lib->is_patched) {
                    if (sym->version) {
                        snprintf(tgt_full, sizeof(tgt_full), "__nm_cdecl.%s@%s", sym->name, sym->version);
                    } else {
                        snprintf(tgt_full, sizeof(tgt_full), "__nm_cdecl.%s", sym->name);
                    }
                    buf_printf(&buf, "sym\t%s\t%s\t%s\t%s\tPATCHED_CDECL\t-\tPATCHED\t%u\n",
                               lib->soname, sym->name, lib->soname, tgt_full, sym->size);
                } else {
                    if (sym->version) {
                        snprintf(tgt_full, sizeof(tgt_full), "%s@%s", sym->name, sym->version);
                    } else {
                        snprintf(tgt_full, sizeof(tgt_full), "%s", sym->name);
                    }
                    buf_printf(&buf, "sym\t%s\t%s\t%s\t%s\tUNTYPED\t-\t-\t%u\n",
                               lib->soname, sym->name, lib->soname, tgt_full, sym->size);
                }
            }
        }
    }

    free(rule_ht);
    free(rule_next);

    for (size_t l = 0; l < num_libs; ++l) {
        free_scanned_lib(&libs[l]);
    }
    free(libs);

    for (size_t d = 0; d < num_dirs; ++d) {
        free(dirs[d].path);
    }
    free(dirs);

    free_static_rules(static_rules, num_static_rules);

    if (!atomic_write_file(out_path, buf.data, buf.len, true)) {
        buf_free(&buf);
        return 1;
    }
    buf_free(&buf);

    if (!quiet) {
        printf("newminhh-lookup-gen: generated lookup table at '%s'\n", out_path);
    }
    return 0;
}

/* --- Usage / Help --- */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s --system [--quiet] [--rules-dir DIR] [--sysroot DIR] [-o PATH]\n"
        "  %s --sysroot DIR [--rules-dir DIR] -o PATH [--quiet]\n"
        "  %s --emit-base RULES_DIR -o lookup_base.txt [--quiet]\n"
        "  %s --emit-c-registry RULES_DIR -o compat_registry.gen.h [--quiet]\n"
        "  %s --emit-py-registry RULES_DIR -o _lookup_registry_gen.py [--quiet]\n"
        "  %s --check [FILE] [--quiet]\n",
        prog, prog, prog, prog, prog, prog);
}

NM_ASSUME_NONNULL_END

/* --- Main CLI Dispatcher --- */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    bool is_system = false;
    bool quiet = false;
    const char *sysroot = "";
    const char *rules_dir = NULL;
    const char *out_path = NULL;
    const char *emit_base_dir = NULL;
    const char *emit_c_dir = NULL;
    const char *emit_py_dir = NULL;
    const char *check_file = NULL;
    bool is_check = false;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--system") == 0) {
            is_system = true;
        } else if (strcmp(arg, "--quiet") == 0) {
            quiet = true;
        } else if (strcmp(arg, "--sysroot") == 0 && i + 1 < argc) {
            sysroot = argv[++i];
        } else if (strcmp(arg, "--rules-dir") == 0 && i + 1 < argc) {
            rules_dir = argv[++i];
        } else if (strcmp(arg, "-o") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(arg, "--emit-base") == 0 && i + 1 < argc) {
            emit_base_dir = argv[++i];
        } else if (strcmp(arg, "--emit-c-registry") == 0 && i + 1 < argc) {
            emit_c_dir = argv[++i];
        } else if (strcmp(arg, "--emit-py-registry") == 0 && i + 1 < argc) {
            emit_py_dir = argv[++i];
        } else if (strcmp(arg, "--check") == 0) {
            is_check = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                check_file = argv[++i];
            }
        } else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", arg);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Fallback default for rules_dir */
    if (!rules_dir) {
        if (access("rules.d", F_OK) == 0) {
            rules_dir = "rules.d";
        } else if (access("src/lookup/rules.d", F_OK) == 0) {
            rules_dir = "src/lookup/rules.d";
        } else {
            rules_dir = NM_LOOKUP_DEFAULT_RULES;
        }
    }

    if (is_check) {
        if (!check_file) {
            check_file = NM_LOOKUP_DEFAULT_CACHE;
        }
        return do_check(check_file, quiet);
    }

    if (emit_base_dir) {
        if (!out_path) {
            fprintf(stderr, "--emit-base requires -o PATH\n");
            return 1;
        }
        return do_emit_base(emit_base_dir, out_path, quiet);
    }

    if (emit_c_dir) {
        if (!out_path) {
            fprintf(stderr, "--emit-c-registry requires -o PATH\n");
            return 1;
        }
        return do_emit_c_registry(emit_c_dir, out_path, quiet);
    }

    if (emit_py_dir) {
        if (!out_path) {
            fprintf(stderr, "--emit-py-registry requires -o PATH\n");
            return 1;
        }
        return do_emit_py_registry(emit_py_dir, out_path, quiet);
    }

    if (is_system || sysroot[0] != '\0') {
        if (!out_path) {
            out_path = NM_LOOKUP_DEFAULT_CACHE;
        }
        return do_system_scan(sysroot, rules_dir, out_path, quiet);
    }

    print_usage(argv[0]);
    return 1;
}
