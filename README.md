# newminhh/lookup

The 11th repository in the [`newminhh`](https://github.com/newminhh/newminhh) ecosystem: layered `i386`-to-`x32` ABI lookup infrastructure for `newminhh`. It provides the lookup table generator (`newminhh-lookup-gen`), shared C23 parser library (`libnmlookup.a`), curated `rules.d/` catalogs, and offline dual-target ABI diffing tooling (`nm-abi-diff.py`) used by compat, dbt, and patcher.

## Role in the System

- **Layered `lookup_table.txt`**: static curated rules are the source of truth, merged into a generated base table; an optional per-machine dynamic cache supplements discovery for locally installed x32 libraries.
- **Curated `rules.d/` catalogs**: versioned `#!newminhh-lookup v1` rule packs under `rules.d/` classify symbols/libraries (`COMPAT`, `NATIVE*`, `PATCHED_CDECL`, `ALIAS`, `UNTYPED`, `FORBIDDEN_ABI`) with signature DSL and flags.
- **Generator/parser**: `newminhh-lookup-gen` builds/validates tables and emits registries (`--emit-base`, `--emit-c-registry`, `--emit-py-registry`); `libnmlookup.a` + `nm_lookup.c` provide the shared C23 parser/lookup API.
- **Multi-distro glibc+musl x32 triggers**: package-manager hooks and optional systemd path units regenerate the dynamic cache non-fatally after x32 library changes. See [`docs/distro_triggers.md`](../../docs/distro_triggers.md) for discovery roots, ELF filtering (`ELFCLASS32` + `EM_X86_64`), and distro integration points.

## Consumers

| Component | Integration |
| :--- | :--- |
| [`src/compat`](../compat/README.md) | Consumes generated C registry (`compat_registry.gen.h`) and lookup resolution for `dlopen`/`dlsym` routing and ABI wrapper dispatch. |
| [`src/dbt`](../dbt/README.md) | Resolves guest symbols/imports through the same lookup precedence for stub binding and runtime ABI decisions. |
| [`src/patcher`](../patcher/README.md) | Uses layered lookup and generated Python registry for ABI classification, Multi-Level Patcher decisions, and safe fallback behavior. |

## Key Files

| Path | Purpose |
| :--- | :--- |
| `Makefile` | Builds `libnmlookup.a`, `newminhh-lookup-gen`, and `lookup_base.txt` |
| `nm_lookup.c` / `lookup_gen.c` | C23 parser/library and lookup table generator/registry emitter |
| `rules.d/*.txt` | Curated static ABI rule packs |
| `tools/nm-abi-diff.py` | Offline dual-target ABI diffing for rule authoring |
| `newminhh-lookup.path` / `newminhh-lookup.service` | Optional systemd path/service integration for cache regeneration |

## Build & Checks

```bash
make -C src/lookup CC=clang all
make -C src/lookup CC=gcc analyze
CC=clang SANITIZE=address,undefined tests/lookup/run_lookup_tests.sh
```

See [`docs/lookup_table.md`](../../docs/lookup_table.md) for schema, signature DSL, merge precedence, and rule-authoring workflow.