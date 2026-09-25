# `struct file_operations` layout + `ashmem_fops` values (MRX-W09, Linux 4.14.116, CFI/LTO)

Static, host-side only. No adb / device and no existing files were touched.
Deliverable: exact field offsets and the values the real `ashmem_fops` holds, plus a
concrete fake-table spec for the ashmem fops hijack.

## 0. Method / why this needed care

`ashmem_fops` (link address `0xffffff8009fee678`, `t` = local, section `.kernel`) is
**all-zero bytes in the ELF file**. This build is a relocatable image: absolute
pointer slots are stored as 0 and filled at load time by `R_AARCH64_RELATIVE`
(type 1027) entries in `.rela.dyn`. Therefore the table was recovered from
`.rela.dyn`, not from `objdump -s`.

ELF facts (`objdump -h`):
- Sections are only `.kernel`, `.kernel2`, `.bss`, `.rela.dyn` — there is no
  separate `.rodata`; the real table's section is `.kernel`.
- `.rela.dyn`: file offset `0x374ccab`, size `0x358170` (= 146,276 × 24-byte `Elf64_Rela`).
  Entry layout confirmed: `r_offset` @+0, `r_info`=0x403=1027 `R_AARCH64_RELATIVE` @+8, `r_addend` @+16.

Cross-check that the read approach is sound:
- `ashmem_misc.fops` slot `0xffffff800b1188a8` has a reloc with addend `0xffffff8009fee678`
  → confirms the fops base address.
- Two independent tables reproduce the known field offsets (see §3).

## 1. Answer to Q1 — dumped words and their symbol matches

The 8 relocated qwords of the real table (offset = slot − `0xffffff8009fee678`):

| Offset | Slot address | Reloc type | Value written at load | Matching symbol |
|---|---|---|---|---|
| `+0x08` | `0xffffff8009fee680` | 1027 | `0xffffff8009e7bad0` | `ashmem_llseek` |
| `+0x20` | `0xffffff8009fee698` | 1027 | `0xffffff8009e7e278` | `ashmem_read_iter` |
| `+0x48` | `0xffffff8009fee6c0` | 1027 | `0xffffff8009e7e454` | `ashmem_ioctl` (`.unlocked_ioctl`) |
| `+0x50` | `0xffffff8009fee6c8` | 1027 | `0xffffff8009e7e458` | `compat_ashmem_ioctl` (`.compat_ioctl`) |
| `+0x58` | `0xffffff8009fee6d0` | 1027 | `0xffffff8009e7e690` | `ashmem_mmap` |
| `+0x60` | `0xffffff8009fee6d8` | 1027 | `0xffffff8009e8b5d0` | `ashmem_open` |
| `+0x70` | `0xffffff8009fee6e8` | 1027 | `0xffffff8009e8b5d4` | `ashmem_release` |

All other qwords in `0x9fee678..0x9fee778` have **no relocation** → they are
literal zero (NULL). That includes `owner` at `+0x00`: `ashmem` is built-in
(`__initcall_36_ashmem_init6`), so `.owner = THIS_MODULE` expands to `NULL` and gets
no reloc. `read`/`write`/`read_iter`'s siblings are NULL because the source only
sets `read_iter`.

### CFI convention (important)

The stored values are the **plain** symbols (e.g. `ashmem_open = 0xffffff8009e8b5d0`),
**not** the `.cfi` aliases. However, the plain symbol is itself a 4-byte `b`
trampoline into the `.cfi` body. Verified by disassembly:

```
ffffff8009e8b5d0 <ashmem_open>:     17c974d5  b  ffffff80090e8924 <ashmem_open.cfi>
ffffff8009e8b5d4 <ashmem_release>:  17c974f9  b  ffffff80090e89b8 <ashmem_release.cfi>
ffffff8009e7bad0 <ashmem_llseek>:   17c9afad  b  ffffff80090e7984 <ashmem_llseek.cfi>
ffffff8009e7e690 <ashmem_mmap>:     17c9a82b  b  ffffff80090e873c <ashmem_mmap.cfi>
ffffff8009e89ae8 <configfs_read_bin_file>:  179abac0  b  ffffff80085385e8 <configfs_read_bin_file.cfi>
ffffff8009e8ac8c <configfs_write_bin_file>: 179ab730  b  ffffff800853894c <configfs_write_bin_file.cfi>
ffffff8009e7ba6c <noop_llseek>:     179727ba  b  ffffff8008445954 <noop_llseek.cfi>
```

So the build's ABI-visible symbol is a stub whose body has the `.cfi` name. The
**fops convention is: store the plain symbol** (which reaches the body via the
stub). The `.cfi` addresses are the actual bodies and are also directly callable.

## 2. Answer to Q2 — definitive `struct file_operations` layout for this build

Source of truth: `include/linux/fs.h:1733-1771`. All members are function/data
pointers → 8 bytes each, natural alignment, no padding. `arm64` implies
`CONFIG_MMU=y`, so the `#ifndef CONFIG_MMU` member `mmap_capabilities` is **absent**.
Size = `0xf0`.

| Offset | Field | `ashmem_fops` value (symbol / NULL) |
|---|---|---|
| `0x00` | `owner` | **NULL** (`THIS_MODULE`==0, built-in) |
| `0x08` | `llseek` | `ashmem_llseek` = `0xffffff8009e7bad0` |
| `0x10` | `read` | NULL |
| `0x18` | `write` | NULL |
| `0x20` | `read_iter` | `ashmem_read_iter` = `0xffffff8009e7e278` |
| `0x28` | `write_iter` | NULL |
| `0x30` | `iterate` | NULL |
| `0x38` | `iterate_shared` | NULL |
| `0x40` | `poll` | NULL |
| `0x48` | `unlocked_ioctl` | `ashmem_ioctl` = `0xffffff8009e7e454` |
| `0x50` | `compat_ioctl` | `compat_ashmem_ioctl` = `0xffffff8009e7e458` |
| `0x58` | `mmap` | `ashmem_mmap` = `0xffffff8009e7e690` |
| `0x60` | `open` | `ashmem_open` = `0xffffff8009e8b5d0` |
| `0x68` | `flush` | NULL |
| `0x70` | `release` | `ashmem_release` = `0xffffff8009e8b5d4` |
| `0x78` | `fsync` | NULL |
| `0x80` | `fasync` | NULL |
| `0x88` | `lock` | NULL |
| `0x90` | `sendpage` | NULL |
| `0x98` | `get_unmapped_area` | NULL |
| `0xa0` | `check_flags` | NULL |
| `0xa8` | `flock` | NULL |
| `0xb0` | `splice_write` | NULL |
| `0xb8` | `splice_read` | NULL |
| `0xc0` | `setlease` | NULL |
| `0xc8` | `fallocate` | NULL |
| `0xd0` | `show_fdinfo` | NULL |
| `0xd8` | `copy_file_range` | NULL |
| `0xe0` | `clone_file_range` | NULL |
| `0xe8` | `dedupe_file_range` | NULL |
| `0xf0` | *(end / sizeof)* | — |

Note: the task's field list mentioned `setfl`; 4.14's `file_operations` has no
`setfl` (that is `file_operations.setfl` was never in this struct version). The
relevant members are exactly those above.

## 3. Answer to Q3 — source initializer order matches the dump

`drivers/staging/android/ashmem.c:848-859` (the only `ashmem.c` in the tree; the
built table matches it exactly):

```c
static const struct file_operations ashmem_fops = {
	.owner = THIS_MODULE,
	.open = ashmem_open,
	.release = ashmem_release,
	.read_iter = ashmem_read_iter,
	.llseek = ashmem_llseek,
	.mmap = ashmem_mmap,
	.unlocked_ioctl = ashmem_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ashmem_ioctl,
#endif
};
```

Designated initializers set fields regardless of textual order; the effective
layout is the struct declaration order, and the dumped slots match:
`.llseek +0x08`, `.read_iter +0x20`, `.unlocked_ioctl +0x48`, `.compat_ioctl +0x50`,
`.mmap +0x58`, `.open +0x60`, `.release +0x70`. Everything not listed is NULL.
(`.read`/`.write` are NOT set by ashmem — confirmed NULL at `+0x10`/`+0x18`.)

Independent cross-validation with two other real tables (from `.rela.dyn`):

```
configfs_bin_file_operations @ 0xffffff8009f02b20   (fs/configfs/file.c:521)
  +0x10 = configfs_read_bin_file   (+0x18) = configfs_write_bin_file
  +0x60 = configfs_open_bin_file   (+0x70) = configfs_release_bin_file
  (+0x08 absent -> llseek == NULL, matching "bin file is not seekable")

configfs_file_operations @ 0xffffff8009f029c0       (fs/configfs/file.c:513)
  +0x08 = generic_file_llseek (+0x10) = configfs_read_file
  +0x18 = configfs_write_file (+0x60) = configfs_open_file (+0x70) = configfs_release
```

Both agree with the table above, so the offsets are definitive.

## 4. Answer to Q4 — concrete fake `file_operations` spec

Aim: `.owner=NULL`, `.llseek=noop_llseek`, `.read=configfs_read_bin_file`,
`.write=configfs_write_bin_file`, and reuse ashmem's `open/release/mmap/ioctl`.
Store the **plain symbols** exactly as the real table does (§1 CFI convention).

| Offset | Field | Value to write | Symbol |
|---|---|---|---|
| `0x00` | `owner` | `0x0000000000000000` | NULL |
| `0x08` | `llseek` | `0xffffff8009e7ba6c` | `noop_llseek` |
| `0x10` | `read` | `0xffffff8009e89ae8` | `configfs_read_bin_file` |
| `0x18` | `write` | `0xffffff8009e8ac8c` | `configfs_write_bin_file` |
| `0x20` | `read_iter` | `0xffffff8009e7e278` *(or 0)* | `ashmem_read_iter` |
| `0x28` | `write_iter` | `0x0000000000000000` | NULL |
| `0x30` | `iterate` | `0x0000000000000000` | NULL |
| `0x38` | `iterate_shared` | `0x0000000000000000` | NULL |
| `0x40` | `poll` | `0x0000000000000000` | NULL |
| `0x48` | `unlocked_ioctl` | `0xffffff8009e7e454` | `ashmem_ioctl` |
| `0x50` | `compat_ioctl` | `0xffffff8009e7e458` | `compat_ashmem_ioctl` |
| `0x58` | `mmap` | `0xffffff8009e7e690` | `ashmem_mmap` |
| `0x60` | `open` | `0xffffff8009e8b5d0` | `ashmem_open` |
| `0x68` | `flush` | `0x0000000000000000` | NULL |
| `0x70` | `release` | `0xffffff8009e8b5d4` | `ashmem_release` |
| `0x78`–`0xe8` | rest | `0x0000000000000000` | NULL |

Total allocation: **`0xf0` bytes**. (On the running device add `g_slide` to every
non-zero value; the real table itself is slid the same way.)

### `.cfi` question — which entries "must" be `.cfi`?

- **Observed convention: none of them.** The real `ashmem_fops` stores the plain
  symbols, which are `b`-trampolines to the `.cfi` bodies. To behave identically,
  write the plain symbols listed above.
- If the exploit framework's validation requires the canonical/body entry points
  instead, the `.cfi` bodies are:

| Plain (fops convention) | `.cfi` body (canonical) |
|---|---|
| `noop_llseek` `0xffffff8009e7ba6c` | `0xffffff8008445954` |
| `configfs_read_bin_file` `0xffffff8009e89ae8` | `0xffffff80085385e8` |
| `configfs_write_bin_file` `0xffffff8009e8ac8c` | `0xffffff800853894c` |
| `ashmem_read_iter` `0xffffff8009e7e278` | `0xffffff80090e7b10` |
| `ashmem_ioctl` `0xffffff8009e7e454` | `0xffffff80090e7c8c` |
| `compat_ashmem_ioctl` `0xffffff8009e7e458` | `0xffffff80090e86f0` |
| `ashmem_mmap` `0xffffff8009e7e690` | `0xffffff80090e873c` |
| `ashmem_open` `0xffffff8009e8b5d0` | `0xffffff80090e8924` |
| `ashmem_release` `0xffffff8009e8b5d4` | `0xffffff80090e89b8` |

Both targets execute the same body (the plain one via a single `b`).

## 5. Uncertain / flags

1. **`.rela.dyn` read-back, not raw rodata.** The file bytes are zero; values come
   from `R_AARCH64_RELATIVE` addends. This is exact for a relocated kernel loaded
   at its link base, which is how `ashmem_misc.fops -> 0xffffff8009fee678` was
   independently confirmed. If the bootloader applies an additional slide, all
   values shift by the same `g_slide` as the symbol table (per `MRX_SYMBOLS_20260926.md`).
2. **CFI on indirect calls.** `__cfi_check` exists in this image, yet ashmem's
   handlers have no `__cfi_<name>` type-id symbol, and the real fops stores plain
   trampolines. This implies the VFS indirect-call path accepts the plain symbol
   (or these types are not checked). I could not fully prove whether a strict
   check would reject an arbitrary plain address; if it does, use the `.cfi` bodies.
   Treat the plain-vs-`.cfi` choice as the one genuinely uncertain point.
3. **Tail offsets (`0x78`–`0xe8`).** Derived from the struct declaration; not
   exercised by `ashmem_fops`/configfs tables (all NULL), so not empirically
   confirmed past `0x70`. They are only needed if the fake table must be full-size
   in place; for a fresh allocation they can remain zero.
4. **`read_iter` choice.** Setting `.read = configfs_read_bin_file` makes `read(2)`
   use it, but `readv(2)`/`preadv` still use `read_iter`. Keeping
   `ashmem_read_iter` preserves ashmem readv semantics; clearing it makes all reads
   go through the configfs path (and non-ITER readv would fail). Pick per exploit need.
5. `ashmem_fops` local symbol size is 0 in the symtab (`objdump -t`), so struct
   size `0xf0` comes from the header, corroborated by the next symbol/canonical layout.

## 6. Reproducer commands (host-side)

```
od = [WORKSPACE]\android-ndk-r20b\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android-objdump.exe
nm = [WORKSPACE]\android-ndk-r20b\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android-nm.exe
img = [FIRMWARE]\MRX-W09\extracted\vmlinux.elf

# zero bytes at the table (proof it is RELA-filled):
& $od -s -j .kernel --start-address=0xffffff8009fee678 --stop-address=0xffffff8009fee6f8 $img

# parse .rela.dyn (off 0x374ccab, 24-byte strides) for slots in [0x9fee678, +0x100)
# r_offset @+0, r_info type=1027 R_AARCH64_RELATIVE @+8, r_addend @+16

# confirm trampolines:
& $od -d --start-address=0xffffff8009e8b5d0 --stop-address=0xffffff8009e8b5d8 $img
```
