#!/usr/bin/env python3
"""Offline dual-target libclang ABI differ for newminhh (#!newminhh-lookup v1).

Compares C header declarations parsed under i386-linux-gnu and
x86_64-linux-gnux32 against exported symbols from target x32 ELF shared
objects, emitting NATIVE_TYPED, FORBIDDEN_ABI, and NATIVE_DATA rules.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import re
import shlex
import subprocess
import sys
from typing import Dict, List, Optional, Set, Tuple

import clang.cindex as ci
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import GNUVerDefSection, GNUVerSymSection


NM_MAX_SIG_ARGS = 16
DEFAULT_X32_SYSROOT = "/home/shadichy/newminhh-x32-sysroot"

_UNSIGNED_INT_KINDS = {
    ci.TypeKind.BOOL,
    ci.TypeKind.UCHAR,
    ci.TypeKind.CHAR_U,
    ci.TypeKind.USHORT,
    ci.TypeKind.CHAR16,
    ci.TypeKind.UINT,
    ci.TypeKind.CHAR32,
    ci.TypeKind.ULONG,
    ci.TypeKind.ULONGLONG,
}

_SIGNED_INT_KINDS = {
    ci.TypeKind.SCHAR,
    ci.TypeKind.CHAR_S,
    ci.TypeKind.SHORT,
    ci.TypeKind.INT,
    ci.TypeKind.WCHAR,
    ci.TypeKind.LONG,
    ci.TypeKind.LONGLONG,
}

_UNSUPPORTED_KINDS = {
    ci.TypeKind.COMPLEX,
    ci.TypeKind.VECTOR,
    ci.TypeKind.EXTVECTOR,
    ci.TypeKind.FLOAT128,
    ci.TypeKind.INT128,
    ci.TypeKind.IBM128,
    ci.TypeKind.HALF,
    ci.TypeKind.FLOAT16,
    ci.TypeKind.BFLOAT16,
}


@dataclass(frozen=True)
class ElfExport:
    """Exported dynamic symbol metadata extracted from an x32 ELF."""

    name: str
    sym_type: str
    size: int
    version: Optional[str]
    is_hidden: bool


def sanitize_token(text: str) -> str:
    """Sanitize a type or field name into a whitespace-free reason token."""
    cleaned = text.strip().replace(" ", "_")
    cleaned = re.sub(r"[^A-Za-z0-9_.:=,-]", "_", cleaned)
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or "anon"


def detect_clang_resource_dir() -> Optional[str]:
    """Return clang's builtin resource directory if available."""
    try:
        out = subprocess.check_output(
            ["clang", "-print-resource-dir"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if out and os.path.isdir(out):
            return out
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def parse_elf_exports(so_path: str) -> Tuple[str, Dict[str, ElfExport]]:
    """Extract DT_SONAME and exported defined symbols with ELF versions."""
    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        soname: Optional[str] = None
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_SONAME":
                        soname = tag.soname
                        break
        if not soname:
            soname = os.path.basename(so_path)

        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is None:
            raise RuntimeError(f"{so_path}: missing .dynsym section")

        versym: Optional[GNUVerSymSection] = None
        verdef: Optional[GNUVerDefSection] = None
        for sec in elf.iter_sections():
            if isinstance(sec, GNUVerSymSection):
                versym = sec
            elif isinstance(sec, GNUVerDefSection):
                verdef = sec

        ver_map: Dict[int, str] = {}
        if verdef is not None:
            for ver, aux_iter in verdef.iter_versions():
                aux_list = list(aux_iter)
                if aux_list:
                    ver_map[int(ver.entry["vd_ndx"])] = aux_list[0].name

        exports: Dict[str, ElfExport] = {}
        for idx, sym in enumerate(dynsym.iter_symbols()):
            if not sym.name:
                continue
            shndx = sym["st_shndx"]
            if shndx in ("SHN_UNDEF", "SHN_ABS"):
                continue
            bind = sym["st_info"]["bind"]
            stype = sym["st_info"]["type"]
            if bind not in ("STB_GLOBAL", "STB_WEAK"):
                continue
            if stype not in ("STT_FUNC", "STT_GNU_IFUNC", "STT_OBJECT"):
                continue

            ver_name: Optional[str] = None
            is_hidden = False
            if versym is not None:
                ndx = versym.get_symbol(idx).entry["ndx"]
                if isinstance(ndx, int):
                    ver_idx = ndx & 0x7FFF
                    is_hidden = bool(ndx & 0x8000)
                    if ver_idx >= 2 and ver_idx in ver_map:
                        ver_name = ver_map[ver_idx]

            candidate = ElfExport(
                name=sym.name,
                sym_type=stype,
                size=int(sym["st_size"]),
                version=ver_name,
                is_hidden=is_hidden,
            )
            prev = exports.get(sym.name)
            # Prefer default (non-hidden) symbol version over hidden legacy ones.
            if prev is None or (prev.is_hidden and not candidate.is_hidden):
                exports[sym.name] = candidate

        return soname, exports


def parse_tu(
    index: ci.Index,
    headers: List[str],
    clang_args: List[str],
    label: str,
) -> ci.TranslationUnit:
    """Parse synthetic header wrapper under the given target flags."""
    inc_lines = []
    for h in headers:
        h_s = h.strip()
        if (h_s.startswith("<") and h_s.endswith(">")) or (
            h_s.startswith('"') and h_s.endswith('"')
        ):
            inc_lines.append(f"#include {h_s}")
        else:
            inc_lines.append(f"#include <{h_s}>")
    src = "\n".join(inc_lines) + "\n"
    tu = index.parse(
        "nm_abi_probe.c",
        args=clang_args,
        unsaved_files=[("nm_abi_probe.c", src)],
        options=ci.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES,
    )
    errors = [d for d in tu.diagnostics if d.severity >= ci.Diagnostic.Error]
    if errors:
        preview = "\n  ".join(str(e) for e in errors[:5])
        raise RuntimeError(f"{label} TU parse failed ({len(errors)} errors):\n  {preview}")
    return tu


def verify_target_probes(
    index: ci.Index,
    i386_args: List[str],
    x32_args: List[str],
) -> None:
    """Assert fundamental ABI type sizes/alignments for i386 and x32 TUs."""
    probe_src = (
        "#include <stdint.h>\n"
        "#include <sys/types.h>\n"
        "#include <time.h>\n"
        "typedef struct { char c; int64_t x; } nm_probe_i64_t;\n"
        "typedef long double nm_probe_ld_t;\n"
        "typedef time_t nm_probe_time_t;\n"
        "typedef off_t nm_probe_off_t;\n"
    )

    def _measure(args: List[str], label: str) -> Dict[str, Tuple[int, int]]:
        tu = index.parse(
            "nm_probe_abi.c",
            args=args,
            unsaved_files=[("nm_probe_abi.c", probe_src)],
        )
        errs = [d for d in tu.diagnostics if d.severity >= ci.Diagnostic.Error]
        if errs:
            raise RuntimeError(f"{label} probe parse failed: {errs[0]}")
        out: Dict[str, Tuple[int, int]] = {}
        for c in tu.cursor.get_children():
            if c.spelling in (
                "nm_probe_i64_t",
                "nm_probe_ld_t",
                "nm_probe_time_t",
                "nm_probe_off_t",
            ):
                t = c.type.get_canonical()
                out[c.spelling] = (t.get_size(), t.get_align())
        return out

    m32 = _measure(i386_args, "i386")
    mx32 = _measure(x32_args, "x32")

    assert m32["nm_probe_time_t"][0] == 4, f"i386 sizeof(time_t)={m32['nm_probe_time_t'][0]} != 4"
    assert m32["nm_probe_off_t"][0] == 4, f"i386 sizeof(off_t)={m32['nm_probe_off_t'][0]} != 4"
    assert m32["nm_probe_i64_t"] == (12, 4), f"i386 i64 probe={m32['nm_probe_i64_t']} != (12, 4)"
    assert m32["nm_probe_ld_t"][0] == 12, f"i386 sizeof(long double)={m32['nm_probe_ld_t'][0]} != 12"

    assert mx32["nm_probe_time_t"][0] == 8, f"x32 sizeof(time_t)={mx32['nm_probe_time_t'][0]} != 8"
    assert mx32["nm_probe_off_t"][0] == 8, f"x32 sizeof(off_t)={mx32['nm_probe_off_t'][0]} != 8"
    assert mx32["nm_probe_i64_t"] == (16, 8), f"x32 i64 probe={mx32['nm_probe_i64_t']} != (16, 8)"
    assert mx32["nm_probe_ld_t"][0] == 16, f"x32 sizeof(long double)={mx32['nm_probe_ld_t'][0]} != 16"


def collect_ast_decls(
    tu: ci.TranslationUnit,
) -> Tuple[Dict[str, ci.Cursor], Dict[str, ci.Cursor]]:
    """Collect file-scope function and global variable declarations from a TU."""
    funcs: Dict[str, ci.Cursor] = {}
    vars_: Dict[str, ci.Cursor] = {}

    def _walk(node: ci.Cursor) -> None:
        for c in node.get_children():
            k = c.kind
            if k == ci.CursorKind.FUNCTION_DECL:
                if c.spelling and c.linkage == ci.LinkageKind.EXTERNAL:
                    # Prefer prototype/declaration with explicit param info if redeclared.
                    prev = funcs.get(c.spelling)
                    if prev is None or (
                        prev.type.kind == ci.TypeKind.FUNCTIONNOPROTO
                        and c.type.kind == ci.TypeKind.FUNCTIONPROTO
                    ):
                        funcs[c.spelling] = c
            elif k == ci.CursorKind.VAR_DECL:
                if c.spelling and c.linkage == ci.LinkageKind.EXTERNAL:
                    vars_[c.spelling] = c
            elif k in (ci.CursorKind.LINKAGE_SPEC, ci.CursorKind.UNEXPOSED_DECL):
                _walk(c)

    _walk(tu.cursor)
    return funcs, vars_


def is_va_list_type(t: ci.Type) -> bool:
    """Detect va_list / __builtin_va_list across i386 and x32 targets."""
    sp = t.spelling
    ct = t.get_canonical()
    csp = ct.spelling
    if "va_list" in sp or "__builtin_va_list" in csp or "__va_list_tag" in csp:
        return True
    if ct.kind == ci.TypeKind.POINTER:
        pt = ct.get_pointee().get_canonical()
        if "__va_list_tag" in pt.spelling:
            return True
    if ct.kind in (ci.TypeKind.CONSTANTARRAY, ci.TypeKind.INCOMPLETEARRAY):
        et = ct.element_type.get_canonical()
        if "__va_list_tag" in et.spelling:
            return True
    return False


def is_fn_ptr_type(t: ci.Type, allow_ptr_to_fnptr: bool = True) -> bool:
    """Detect direct function types, function pointers, or pointers to function pointers."""
    ct = t.get_canonical()
    if ct.kind in (ci.TypeKind.FUNCTIONPROTO, ci.TypeKind.FUNCTIONNOPROTO):
        return True
    if ct.kind == ci.TypeKind.POINTER:
        pt = ct.get_pointee().get_canonical()
        if pt.kind in (ci.TypeKind.FUNCTIONPROTO, ci.TypeKind.FUNCTIONNOPROTO):
            return True
        if allow_ptr_to_fnptr and pt.kind == ci.TypeKind.POINTER:
            ppt = pt.get_pointee().get_canonical()
            if ppt.kind in (ci.TypeKind.FUNCTIONPROTO, ci.TypeKind.FUNCTIONNOPROTO):
                return True
    return False


def diff_pointee_type(
    t1: ci.Type,
    t2: ci.Type,
    visited: Set[Tuple[str, str]],
    fnptr_notes: List[str],
    allow_struct_fnptr: bool = True,
) -> Optional[str]:
    """Recursively compare pointee/nested types across i386 and x32."""
    c1 = t1.get_canonical()
    c2 = t2.get_canonical()

    if is_va_list_type(t1) or is_va_list_type(t2):
        return "va_list"

    if c1.kind == ci.TypeKind.VOID and c2.kind == ci.TypeKind.VOID:
        return None

    if c1.kind == ci.TypeKind.LONGDOUBLE or c2.kind == ci.TypeKind.LONGDOUBLE:
        return "long-double"

    if c1.kind in _UNSUPPORTED_KINDS or c2.kind in _UNSUPPORTED_KINDS:
        return f"unsupported-type:{sanitize_token(t1.spelling)}"

    if c1.kind == ci.TypeKind.POINTER and c2.kind == ci.TypeKind.POINTER:
        p1 = c1.get_pointee().get_canonical()
        p2 = c2.get_pointee().get_canonical()
        if p1.kind in (ci.TypeKind.FUNCTIONPROTO, ci.TypeKind.FUNCTIONNOPROTO) or p2.kind in (
            ci.TypeKind.FUNCTIONPROTO,
            ci.TypeKind.FUNCTIONNOPROTO,
        ):
            if allow_struct_fnptr:
                return None
            return "callback-fn-ptr"
        return diff_pointee_type(c1.get_pointee(), c2.get_pointee(), visited, fnptr_notes, allow_struct_fnptr)

    if c1.kind in (ci.TypeKind.CONSTANTARRAY, ci.TypeKind.INCOMPLETEARRAY) and c2.kind in (
        ci.TypeKind.CONSTANTARRAY,
        ci.TypeKind.INCOMPLETEARRAY,
    ):
        if c1.kind == ci.TypeKind.CONSTANTARRAY and c2.kind == ci.TypeKind.CONSTANTARRAY:
            s1, s2 = c1.get_size(), c2.get_size()
            if s1 != s2:
                return f"array-size:{sanitize_token(t1.spelling)}:i386={s1},x32={s2}"
        return diff_pointee_type(c1.element_type, c2.element_type, visited, fnptr_notes, allow_struct_fnptr)

    if c1.kind == ci.TypeKind.RECORD and c2.kind == ci.TypeKind.RECORD:
        return diff_record(c1, c2, t1.spelling, visited, fnptr_notes)

    if c1.kind in (ci.TypeKind.FUNCTIONPROTO, ci.TypeKind.FUNCTIONNOPROTO) and c2.kind in (
        ci.TypeKind.FUNCTIONPROTO,
        ci.TypeKind.FUNCTIONNOPROTO,
    ):
        return None if allow_struct_fnptr else "callback-fn-ptr"

    s1, s2 = c1.get_size(), c2.get_size()
    if s1 != s2:
        return f"pointee-size:{sanitize_token(t1.spelling)}:i386={s1},x32={s2}"

    if c1.kind != c2.kind:
        # Allow equivalent 32-bit int/long or unsigned int/unsigned long across ILP32 targets.
        if (c1.kind in _SIGNED_INT_KINDS and c2.kind in _SIGNED_INT_KINDS and s1 == s2) or (
            c1.kind in _UNSIGNED_INT_KINDS and c2.kind in _UNSIGNED_INT_KINDS and s1 == s2
        ):
            return None
        return f"pointee-kind:{sanitize_token(t1.spelling)}:{c1.kind.name}_vs_{c2.kind.name}"

    return None


def _is_strictly_ilp32_invariant_record(
    rec: ci.Type,
    visited: Set[str],
    fnptr_notes: List[str],
) -> bool:
    """Return True iff a complete x32 record uses exclusively 32-bit ILP32-invariant types.

    Used only when the i386 header forward-declares a struct as opaque (e.g. due
    to minor library header version skew) while the x32 header defines it.
    Any 64-bit scalar, >4-byte alignment, or non-trivial pointee rejects it.
    """
    if rec.spelling in visited:
        return True
    visited.add(rec.spelling)
    if rec.get_size() < 0 or rec.get_align() > 4:
        return False
    for f in rec.get_fields():
        if is_fn_ptr_type(f.type, allow_ptr_to_fnptr=False):
            fnptr_notes.append(f"{sanitize_token(rec.spelling)}.{sanitize_token(f.spelling or 'anon')}")
            continue
        if not _is_strictly_ilp32_invariant_type(f.type, visited, fnptr_notes):
            return False
    return True


def _is_strictly_ilp32_invariant_type(
    t: ci.Type,
    visited: Set[str],
    fnptr_notes: List[str],
) -> bool:
    ct = t.get_canonical()
    if is_va_list_type(t):
        return False
    if ct.kind in _UNSUPPORTED_KINDS or ct.kind == ci.TypeKind.LONGDOUBLE:
        return False
    if ct.kind == ci.TypeKind.POINTER:
        pt = ct.get_pointee().get_canonical()
        if pt.kind == ci.TypeKind.VOID:
            return True
        if pt.kind in (ci.TypeKind.FUNCTIONPROTO, ci.TypeKind.FUNCTIONNOPROTO):
            return False
        if pt.kind == ci.TypeKind.RECORD:
            return pt.get_size() < 0 or _is_strictly_ilp32_invariant_record(pt, visited, fnptr_notes)
        return _is_strictly_ilp32_invariant_type(pt, visited, fnptr_notes)
    if ct.kind == ci.TypeKind.CONSTANTARRAY:
        return _is_strictly_ilp32_invariant_type(ct.element_type, visited, fnptr_notes)
    if ct.kind == ci.TypeKind.RECORD:
        return _is_strictly_ilp32_invariant_record(ct, visited, fnptr_notes)
    sz = ct.get_size()
    al = ct.get_align()
    if sz <= 0 or sz > 4 or al <= 0 or al > 4:
        return False
    return ct.kind in _SIGNED_INT_KINDS or ct.kind in _UNSIGNED_INT_KINDS or ct.kind in (
        ci.TypeKind.ENUM,
        ci.TypeKind.FLOAT,
    )


def diff_record(
    c1: ci.Type,
    c2: ci.Type,
    display_name: str,
    visited: Set[Tuple[str, str]],
    fnptr_notes: List[str],
) -> Optional[str]:
    """Compare complete struct/union layout recursively across i386 and x32."""
    key = (c1.spelling, c2.spelling)
    if key in visited:
        return None
    visited.add(key)

    s1, s2 = c1.get_size(), c2.get_size()
    if s1 < 0 and s2 < 0:
        # Opaque / incomplete record pointer is safe.
        return None
    if s1 < 0 and s2 >= 0:
        if _is_strictly_ilp32_invariant_record(c2, set(), fnptr_notes):
            return None
        return f"opaque-mismatch:{sanitize_token(display_name)}"
    if (s1 < 0) != (s2 < 0):
        return f"opaque-mismatch:{sanitize_token(display_name)}"

    name_tok = sanitize_token(c1.spelling or display_name)
    if s1 != s2:
        return f"struct-layout:{name_tok}:size_i386={s1},x32={s2}"

    a1, a2 = c1.get_align(), c2.get_align()
    if a1 != a2 and max(a1, a2) >= 16:
        return f"struct-align:{name_tok}:i386={a1},x32={a2}"

    f1 = list(c1.get_fields())
    f2 = list(c2.get_fields())
    if len(f1) != len(f2):
        return f"struct-layout:{name_tok}:nfields_{len(f1)}_vs_{len(f2)}"

    for x, y in zip(f1, f2):
        fld_tok = sanitize_token(x.spelling or "anon")
        if x.is_bitfield() != y.is_bitfield():
            return f"struct-bitfield:{name_tok}.{fld_tok}"
        if x.is_bitfield() and x.get_bitfield_width() != y.get_bitfield_width():
            return f"struct-bitfield-width:{name_tok}.{fld_tok}"

        o1 = x.get_field_offsetof()
        o2 = y.get_field_offsetof()
        if o1 != o2:
            return f"struct-offset:{name_tok}.{fld_tok}:i386={o1},x32={o2}"

        ft1 = x.type.get_canonical()
        ft2 = y.type.get_canonical()
        fs1, fs2 = ft1.get_size(), ft2.get_size()
        if fs1 != fs2:
            return f"struct-field-size:{name_tok}.{fld_tok}:i386={fs1},x32={fs2}"

        if is_fn_ptr_type(x.type, allow_ptr_to_fnptr=False):
            fnptr_notes.append(f"{name_tok}.{fld_tok}")
            continue

        sub = diff_pointee_type(x.type, y.type, visited, fnptr_notes, allow_struct_fnptr=True)
        if sub:
            return sub

    return None


def map_abi_type(
    t1: ci.Type,
    t2: ci.Type,
    is_ret: bool,
    arg_label: str,
    fnptr_notes: List[str],
) -> Tuple[Optional[str], Optional[str]]:
    """Map a matched i386/x32 type pair to a DSL char or FORBIDDEN_ABI reason."""
    if is_va_list_type(t1) or is_va_list_type(t2):
        return None, "va_list"

    c1 = t1.get_canonical()
    c2 = t2.get_canonical()

    if c1.kind == ci.TypeKind.VOID and c2.kind == ci.TypeKind.VOID:
        return ("v", None) if is_ret else (None, f"void-param:{arg_label}")

    if c1.kind == ci.TypeKind.LONGDOUBLE or c2.kind == ci.TypeKind.LONGDOUBLE:
        return None, "long-double"

    if c1.kind in _UNSUPPORTED_KINDS or c2.kind in _UNSUPPORTED_KINDS:
        return None, f"unsupported-type:{sanitize_token(t1.spelling)}"

    if is_fn_ptr_type(t1) or is_fn_ptr_type(t2):
        return None, "callback-fn-ptr"

    if c1.kind == ci.TypeKind.RECORD or c2.kind == ci.TypeKind.RECORD:
        tname = sanitize_token(t1.spelling or c1.spelling)
        return None, (f"sret:{tname}" if is_ret else f"agg-param:{tname}")

    # Pointer or parameter-decayed array.
    ptr_kinds = (ci.TypeKind.POINTER, ci.TypeKind.CONSTANTARRAY, ci.TypeKind.INCOMPLETEARRAY)
    if c1.kind in ptr_kinds and c2.kind in ptr_kinds:
        if c1.kind == ci.TypeKind.POINTER and c2.kind == ci.TypeKind.POINTER:
            p1, p2 = c1.get_pointee(), c2.get_pointee()
        elif not is_ret and c1.kind != ci.TypeKind.POINTER and c2.kind != ci.TypeKind.POINTER:
            p1, p2 = c1.element_type, c2.element_type
        else:
            p1 = c1.get_pointee() if c1.kind == ci.TypeKind.POINTER else c1.element_type
            p2 = c2.get_pointee() if c2.kind == ci.TypeKind.POINTER else c2.element_type
        diff = diff_pointee_type(p1, p2, set(), fnptr_notes, allow_struct_fnptr=True)
        if diff:
            return None, diff
        return "p", None

    s1, s2 = c1.get_size(), c2.get_size()
    t_tok = sanitize_token(t1.spelling or arg_label)
    if s1 != s2:
        return None, f"scalar-size:{t_tok}:i386={s1},x32={s2}"
    if s1 <= 0 or s1 > 8:
        return None, f"scalar-size:{t_tok}:i386={s1},x32={s2}"

    if c1.kind == ci.TypeKind.FLOAT and c2.kind == ci.TypeKind.FLOAT:
        return "f", None
    if c1.kind == ci.TypeKind.DOUBLE and c2.kind == ci.TypeKind.DOUBLE:
        return "d", None

    if c1.kind == ci.TypeKind.ENUM and c2.kind == ci.TypeKind.ENUM:
        return ("q" if s1 == 8 else "i"), None

    if c1.kind in _SIGNED_INT_KINDS and c2.kind in _SIGNED_INT_KINDS:
        return ("q" if s1 == 8 else "i"), None

    if c1.kind in _UNSIGNED_INT_KINDS and c2.kind in _UNSIGNED_INT_KINDS:
        return ("Q" if s1 == 8 else "u"), None

    return None, f"scalar-mismatch:{t_tok}:{c1.kind.name}_vs_{c2.kind.name}"


def analyze_function(
    c1: ci.Cursor,
    c2: ci.Cursor,
) -> Tuple[Optional[str], Optional[str], List[str]]:
    """Evaluate a matched function declaration across i386 and x32."""
    if c1.type.kind == ci.TypeKind.FUNCTIONNOPROTO or c2.type.kind == ci.TypeKind.FUNCTIONNOPROTO:
        return None, "unprototyped", []
    if c1.type.is_function_variadic() or c2.type.is_function_variadic():
        return None, "variadic", []

    args1 = list(c1.get_arguments())
    args2 = list(c2.get_arguments())
    if len(args1) != len(args2):
        return None, f"arg-count-mismatch:i386={len(args1)},x32={len(args2)}", []
    if len(args1) > NM_MAX_SIG_ARGS:
        return None, f"too-many-args:{len(args1)}", []

    fnptr_notes: List[str] = []
    ret_ch, reason = map_abi_type(c1.result_type, c2.result_type, True, "ret", fnptr_notes)
    if reason:
        return None, reason, fnptr_notes

    arg_chars: List[str] = []
    for idx, (a1, a2) in enumerate(zip(args1, args2)):
        ch, reason = map_abi_type(a1.type, a2.type, False, f"arg{idx}", fnptr_notes)
        if reason:
            return None, reason, fnptr_notes
        assert ch is not None
        arg_chars.append(ch)

    assert ret_ch is not None
    sig = f"{ret_ch}:{''.join(arg_chars)}"
    return sig, None, fnptr_notes


def analyze_data_symbol(
    v1: ci.Cursor,
    v2: ci.Cursor,
    elf_sym: ElfExport,
) -> Tuple[Optional[int], Optional[str]]:
    """Evaluate an exported STT_OBJECT global across i386 and x32."""
    s1 = v1.type.get_canonical().get_size()
    s2 = v2.type.get_canonical().get_size()
    if s1 <= 0 or s2 <= 0:
        return None, f"data-incomplete:{sanitize_token(elf_sym.name)}"
    if s1 != s2:
        return None, f"data-size:{sanitize_token(elf_sym.name)}:i386={s1},x32={s2}"
    if elf_sym.size > 0 and elf_sym.size != s2:
        return None, f"data-elf-size:{sanitize_token(elf_sym.name)}:elf={elf_sym.size},ast={s2}"
    return s2, None


def format_target_sym(sym: ElfExport) -> str:
    """Format col 5 (<sym>[@<ver>]) when ELF version is present."""
    if sym.version:
        return f"{sym.name}@{sym.version}"
    return sym.name


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline dual-target libclang ABI differ for #!newminhh-lookup v1"
    )
    parser.add_argument(
        "--x32-sysroot",
        default=DEFAULT_X32_SYSROOT,
        help=f"Path to x32 sysroot (default: {DEFAULT_X32_SYSROOT})",
    )
    parser.add_argument(
        "--so",
        action="append",
        required=True,
        help="Target x32 ELF shared object (.so); repeatable",
    )
    parser.add_argument(
        "--header",
        action="append",
        required=True,
        help="C header to #include (e.g. zlib.h or '<GL/gl.h>'); repeatable",
    )
    parser.add_argument(
        "--flag",
        action="append",
        default=[],
        help="Extra clang flag passed to BOTH i386 and x32 TUs; repeatable",
    )
    parser.add_argument(
        "--i386-flag",
        action="append",
        default=[],
        help="Extra clang flag passed ONLY to i386 TU; repeatable",
    )
    parser.add_argument(
        "--x32-flag",
        action="append",
        default=[],
        help="Extra clang flag passed ONLY to x32 TU; repeatable",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="Output rules.d file path (default: stdout)",
    )
    raw_argv = list(sys.argv[1:])
    norm_argv: List[str] = []
    i = 0
    while i < len(raw_argv):
        tok = raw_argv[i]
        if tok in ("--flag", "--i386-flag", "--x32-flag") and i + 1 < len(raw_argv):
            norm_argv.append(f"{tok}={raw_argv[i + 1]}")
            i += 2
        else:
            norm_argv.append(tok)
            i += 1
    args = parser.parse_args(norm_argv)

    res_dir = detect_clang_resource_dir()
    common_res = ["-resource-dir", res_dir] if res_dir else []
    i386_args = ["-x", "c", "-target", "i386-linux-gnu"] + common_res + args.flag + args.i386_flag
    x32_args = (
        ["-x", "c", "-target", "x86_64-linux-gnux32", f"--sysroot={args.x32_sysroot}"]
        + common_res
        + args.flag
        + args.x32_flag
    )

    idx = ci.Index.create()
    verify_target_probes(idx, i386_args, x32_args)

    tu_i386 = parse_tu(idx, args.header, i386_args, "i386")
    tu_x32 = parse_tu(idx, args.header, x32_args, "x32")

    f32, v32 = collect_ast_decls(tu_i386)
    fx32, vx32 = collect_ast_decls(tu_x32)
    common_funcs = set(f32) & set(fx32)
    common_vars = set(v32) & set(vx32)

    lib_lines: List[str] = []
    sym_lines: List[str] = []
    vtable_warnings: List[str] = []
    counts = {"NATIVE_TYPED": 0, "FORBIDDEN_ABI": 0, "NATIVE_DATA": 0}

    seen_sonames: Set[str] = set()
    for so_path in args.so:
        soname, exports = parse_elf_exports(so_path)
        if soname not in seen_sonames:
            seen_sonames.add(soname)
            lib_lines.append(f"lib\t{soname}\t-\t{soname}\t-\tNATIVE\t-\t-\t-")

        for sym_name in sorted(exports):
            exp = exports[sym_name]
            if exp.sym_type in ("STT_FUNC", "STT_GNU_IFUNC"):
                if sym_name not in common_funcs:
                    continue
                sig, reason, fnptr_notes = analyze_function(f32[sym_name], fx32[sym_name])
                if reason is not None:
                    counts["FORBIDDEN_ABI"] += 1
                    sym_lines.append(
                        f"sym\t{soname}\t{sym_name}\t-\t-\tFORBIDDEN_ABI\t-\tREASON={reason}\t0"
                    )
                else:
                    assert sig is not None
                    counts["NATIVE_TYPED"] += 1
                    tgt = format_target_sym(exp)
                    sym_lines.append(
                        f"sym\t{soname}\t{sym_name}\t{soname}\t{tgt}\tNATIVE_TYPED\t{sig}\t-\t0"
                    )
                    if fnptr_notes:
                        uniq_notes = sorted(set(fnptr_notes))
                        vtable_warnings.append(
                            f"# NOTE: {soname}:{sym_name} struct fn-ptr field(s): {','.join(uniq_notes)}"
                        )
            elif exp.sym_type == "STT_OBJECT":
                if sym_name not in common_vars:
                    continue
                sz, reason = analyze_data_symbol(v32[sym_name], vx32[sym_name], exp)
                if reason is not None:
                    counts["FORBIDDEN_ABI"] += 1
                    sym_lines.append(
                        f"sym\t{soname}\t{sym_name}\t-\t-\tFORBIDDEN_ABI\t-\tREASON={reason}\t0"
                    )
                else:
                    assert sz is not None
                    counts["NATIVE_DATA"] += 1
                    tgt = format_target_sym(exp)
                    sym_lines.append(
                        f"sym\t{soname}\t{sym_name}\t{soname}\t{tgt}\tNATIVE_DATA\tD{sz}\tDATA\t{sz}"
                    )

    clang_ver_obj = ci.conf.lib.clang_getClangVersion()
    clang_ver = getattr(clang_ver_obj, "spelling", str(clang_ver_obj))
    if isinstance(clang_ver, bytes):
        clang_ver = clang_ver.decode("utf-8", errors="replace")
    cmd_str = " ".join(shlex.quote(a) for a in sys.argv)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    out_lines = [
        "#!newminhh-lookup v1",
        f"# Generated by: {cmd_str}",
        f"# Timestamp: {ts}",
        f"# Libclang: {clang_ver}",
        f"# Targets: i386-linux-gnu vs x86_64-linux-gnux32 (sysroot={args.x32_sysroot})",
        (
            f"# Counts: NATIVE_TYPED={counts['NATIVE_TYPED']} "
            f"FORBIDDEN_ABI={counts['FORBIDDEN_ABI']} "
            f"NATIVE_DATA={counts['NATIVE_DATA']}"
        ),
    ]
    if vtable_warnings:
        out_lines.append(f"# Struct vtable warnings ({len(vtable_warnings)} NATIVE_TYPED syms):")
        out_lines.extend(vtable_warnings)
    out_lines.append("")
    out_lines.extend(lib_lines)
    out_lines.extend(sym_lines)

    payload = "\n".join(out_lines) + "\n"
    if args.output == "-":
        sys.stdout.write(payload)
    else:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as out_f:
            out_f.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
