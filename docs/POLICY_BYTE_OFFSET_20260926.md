# Binary SELinux policy (`precompiled_sepolicy`) — section offsets and the exact
# `policydb.permissive_map` patch

Date: 2026-09-26
Scope: host-side static analysis. No device, no adb. No existing file was modified.
New files created: `ghostlock_pocs\polpatch.py` and this report. The patched test
blob was written only under the temp dir.

Input blob: `[WORKSPACE]\binder_uaf\session_20260824\precompiled_sepolicy`
(989,730 bytes = 0xF1A22, magic `0xf97cff8c`).

Ground truth used: the shipped Huawei 4.14 kernel source
`huawei_kernel_src\Code_Opensource\kernel\security\selinux\ss\`
(`policydb.c`, `ebitmap.c`, `avtab.c`, `conditional.c`), mirrored against
`external\selinux\libsepol\src\policydb.c`. The version constants in
`ss\...\include\security.h` and `libsepol\include\sepol\policydb\policydb.h`
are identical (BASE 15 … XPERMS_IOCTL 30, INFINIBAND 31).

---

## 0. Executive answer

* The policy is **version 30** (`POLICYDB_VERSION_XPERMS_IOCTL`), MLS, one user, 97 classes.
* `policydb.permissive_map` starts at **file offset `0x38` (56)** and is currently
  **empty**: 12 bytes `40 00 00 00 | 00 00 00 00 | 00 00 00 00`
  (mapunit 64, highbit 0, count 0).
* To mark **type value 1153 (name `shell`)** permissive, replace the 12 bytes at
  `0x38` with **24 bytes** and keep the rest shifted by **+12**:

```
file offset  size  bytes (little-endian)        field
0x38         4     40 00 00 00                  permissive_map.mapunit = 64
0x3c         4     c0 04 00 00                  permissive_map.highbit = 1216 (0x4c0)
0x40         4     01 00 00 00                  permissive_map.count  = 1
0x44         4     80 04 00 00                  node[0].startbit = 1152 (0x480)
0x48         8     02 00 00 00 00 00 00 00      node[0].map = 0x0000000000000002
```

* Result: 989,730 + 12 = **989,742 bytes**. Verified by re-parsing: type 1153 is set
  and the parser consumes exactly 989,742 bytes.

Type value 1153 was confirmed to be the **name `shell`** by reading it straight out
of the blob's own `types` symbol table (not assumed): `type_val_to_name[1153] == "shell"`.
The CIL source also has `(type shell)` at
`binder_uaf\session_20260913\device_plat_sepolicy.cil:3398`. There is no
`(typepermissive ...)` anywhere in the CIL.

---

## 1. Parsed header

`ss\policydb.c:2287-2393`. The u32 at file offset `0x04` is **not** the version — it is
`strlen`; the version is the first u32 of the *second* group (offset `0x10`). There is
**no `seqno` field** in this format (see §5).

| file offset | size | value | meaning |
|---|---|---|---|
| `0x00` | 4 | `0xf97cff8c` | `POLICYDB_MAGIC` (`SELINUX_MAGIC`) |
| `0x04` | 4 | 8 | `strlen` of the policy string (`POLICYDB_STRING`) |
| `0x08` | 8 | `"SE Linux"` | identifier string, no NUL |
| `0x10` | 4 | **30** | `policyvers` = `POLICYDB_VERSION_XPERMS_IOCTL` |
| `0x14` | 4 | `0x00000001` | `config`; bit0 = `POLICYDB_CONFIG_MLS` → **MLS enabled** |
| `0x18` | 4 | 8 | `sym_num` (`SYM_NUM`) |
| `0x1c` | 4 | 7 | `ocon_num` (`OCON_NUM-2`, matches `policydb_compat[30]`) |

Because `policyvers=30`:
* `>= POLCAP (22)` → read `policycaps` ebitmap
* `>= PERMISSIVE (23)` → read `permissive_map` ebitmap
* `>= BOUNDARY (24)` → roles/types/users carry a `bounds` word
* `>= VALIDATETRANS (19)`, `>= FILENAME_TRANS (25)`, `>= ROLETRANS (26)`,
  `>= NEW_OBJECT_DEFAULTS (27)`, `>= DEFAULT_TYPE (28)`,
  `>= CONSTRAINT_NAMES (29)`, `>= XPERMS_IOCTL (30)` → all apply
* `>= MLS (19)` → every context carries an MLS range; `range_trans` section present
* `< INFINIBAND (31)` → `ocon_num = 7`, so nodes 0..6 only (no ibpkey/ibendport)

---

## 2. Every section walked, in `policydb_read` order, with offsets

Offsets are `[start, end)` in the **original** blob. The `polpatch.py` walk ends at
exactly `0xF1A22` (= file size), which is the proof that the layout is right.

```
[0x00000000, 0x00000010)     16  magic + strlen + "SE Linux"
[0x00000010, 0x00000020)     16  policyvers + config + sym_num + ocon_num
[0x00000020, 0x00000038)     24  ebitmap policycaps   (mapunit=64 highbit=64 count=1; entry 0x0:0x27 -> bits {0,1,2,5})
[0x00000038, 0x00000044)     12  ebitmap permissive_map  (mapunit=64 highbit=0 count=0)   <-- TARGET
[0x00000044, 0x000005f7)   1459  symtab[0]=commons   nprim=5    nel=5
[0x000005f7, 0x0000e174)  56189  symtab[1]=classes   nprim=97   nel=97
[0x0000e174, 0x0000e3d7)    611  symtab[2]=roles     nprim=4    nel=4
[0x0000e3d7, 0x000241c4)  89581  symtab[3]=types     nprim=2676 nel=2683   (binary says 1153 == "shell")
[0x000241c4, 0x000242e5)    289  symtab[4]=users     nprim=1    nel=1
[0x000242e5, 0x000242ed)      8  symtab[5]=bools     nprim=0    nel=0
[0x000242ed, 0x000243cf)    226  symtab[6]=levels    nprim=1    nel=1
[0x000243cf, 0x00028381)  16306  symtab[7]=cats      nprim=1024 nel=1024
[0x00028381, 0x000c973d) 660412  avtab:te_avtab      nel=53779
[0x000c973d, 0x000c9741)      4  cond_list           nodes=0
[0x000c9741, 0x000c9745)      4  role_trans          nel=0
[0x000c9745, 0x000c9749)      4  role_allow          nel=0
[0x000c9749, 0x000c97fc)    179  filename_trans      nel=6
[0x000c97fc, 0x000c9bcc)    976  ocontext[0]=isid    nel=27
[0x000c9bcc, 0x000c9bd0)      4  ocontext[1]=fs      nel=0
[0x000c9bd0, 0x000c9bd4)      4  ocontext[2]=port    nel=0
[0x000c9bd4, 0x000c9bd8)      4  ocontext[3]=netif   nel=0
[0x000c9bd8, 0x000c9bdc)      4  ocontext[4]=node    nel=0
[0x000c9bdc, 0x000c9f0f)    819  ocontext[5]=fsuse   nel=18
[0x000c9f0f, 0x000c9f13)      4  ocontext[6]=node6   nel=0
[0x000c9f13, 0x000da34e)  66619  genfs               fstypes=25 entries=896
[0x000da34e, 0x000da352)      4  range_trans         nel=0
[0x000da352, 0x000f1a22)  95952  type_attr_map       2676 ebitmaps (== symtab[3].nprim)
                                   EOF at 0xF1A22 == file size
```

Note the two count subtleties that a naive reader gets wrong and that the exact-EOF
check catches:
* `symtab[3]=types` has **nprim=2676 but nel=2683**. The `type_attr_map` loop runs
  `p->p_types.nprim` = **2676** times (`policydb.c:2523`), not `nel`. Using 2683
  overshoots; using 2676 lands exactly on EOF.
* `symtab[5]=bools` is empty (nprim=0, nel=0) even for v30.

### Device-side hardcode (if a tiny on-device patcher is preferred)

Only the offset and the 15/24-byte write are needed; the rest is a straight copy:
* read `[0x00, 0x38)`, emit 24 new bytes `40 00 00 00 c0 04 00 00 01 00 00 00
  80 04 00 00 02 00 00 00 00 00 00 00`, then emit `[0x44, EOF)` unchanged.
* Everything at/after `0x44` moves **+12**; new size 989,742. There is no length,
  offset, checksum, hash or signature field anywhere in the header
  (`policydb_read` is a pure sequential walk, `policydb.c:2534-2539`).

---

## 3. The on-disk ebitmap encoding (what `highbit`/`count`/node really are)

From `ss\ebitmap.c:365-468` (`ebitmap_read`) and `:470-545` (`ebitmap_write`):

```
u32 mapunit        # must equal BITS_PER_U64 = 64, else -EINVAL
u32 highbit        # writer stores roundup(max_set_bit+1, 64); reader rounds UP to 384
u32 count          # number of 64-bit words that contain >=1 set bit
count * { u32 startbit; u64 map }   # startbit is a multiple of 64
```

* **There is no 384-bit on-disk unit.** One disk entry is one **64-bit word**
  (`startbit`, `map`). The 384-bit `EBITMAP_SIZE` grouping is created only in memory
  when `ebitmap_read` merges consecutive entries whose `startbit` fall in the same
  384-bit window (`ebitmap.c:423-444`). So "node" in the file == 64-bit word.
* Bit `b`: `startbit = b - (b % 64)`, and `map` bit `(b % 64)` is set.
* The reader validates `mapunit==64`, `startbit % 64 == 0`, and, after rounding
  `highbit` up to 384, `startbit <= highbit - 64`.
* `highbit == 0` makes the reader ignore the entries entirely (`node = NULL`), so any
  non-empty map must have a non-zero highbit.
* For target bit **1153**: `startbit = 1152`, `map = 1 << 1 = 0x2`.
  The canonical `ebitmap_write` highbit is `roundup(1154, 64) = 1216`.

The same encoding was independently observed in the file's own `policycaps`
(`highbit=64, count=1, startbit=0, map=0x27` → bits {0,1,2,5}), and in every
`type_attr_map` ebitmap; all compiled blobs use EXACTLY this on-disk form.

### `highbit` choice: 1216 vs 1153

Both are accepted by `ebitmap_read` because it rounds `highbit` up to a multiple of
384: `1216 -> 1536` and `1153 -> 1536`. This report/script use the canonical
**1216 (0x4c0)**, i.e. what `ebitmap_write` emits. The earlier
`POLICY_LOAD_ROUTE_20260926.md` used `1153 (0x481)`; that also loads. Either is fine;
`1216` is the "writer-faithful" value.

---

## 4. `polpatch.py`

Path: `[WORKSPACE]\ghostlock_pocs\polpatch.py`.
Usage: `python polpatch.py <in> <out> [typevalue]` (default 1153). It is pure stdlib.

It implements a faithful `policydb_read` walk (§2 order, all v30 gates), so it locates
`permissive_map` by **consuming every preceding section**, not by guessing. It then
decodes the current permissive set, sets the requested bit, re-encodes the bitmap with
`ebitmap_write` semantics, splices it in, re-parses the output, and asserts both the
bit is set and the walk again consumes the whole file. It refuses an output whose walk
does not end at EOF. `type_val_to_name` is read from the types symtab so the target's
name is reported.

Observed run (writing only to the temp dir):

```
policyvers : 30 (0x1e)
config     : MLS=1
target type value     : 1153 (shell)
permissive_map offset : 0x38 (56)
permissive_map end    : 0x44
encoding              : mapunit=64 highbit=0 count=0
current permissive set: (empty)
policycaps bits       : [0, 1, 2, 5]
== patch ==
old map bytes (len 12): 40 00 00 00 00 00 00 00 00 00 00 00
new map bytes (len 24): 40 00 00 00 c0 04 00 00 01 00 00 00 80 04 00 00 02 00 00 00 00 00 00 00
size delta            : +12
new permissive set    : [1153]
== verify (re-parse out) ==
bit 1153 set            : True
re-parsed permissive   : [1153]
permissive_map offset  : 0x38
walk consumed file     : True (989742 of 989742 bytes)
VERIFY OK
```

Additional tests:
* Re-running on the already-patched output is idempotent: `already permissive: True`,
  new bytes identical, `size delta: +0`, `VERIFY OK`.
* Truncated input (first 5000 bytes) → `PARSE ERROR: truncated: need 4 byte(s) at
  file offset 0x1385 but only 3 left`, exit 3 (no silent wrong offset).
* Version byte forced to 99 → `PARSE ERROR: policyvers 99 outside 15..31`, exit 3.

---

## 5. Uncertainty / honest caveats

1. **Format is parsed with certainty for this blob.** Every one of the ~30 sections
   consumed in `policydb_read` order ends at exactly EOF (0xF1A22), and the version
   gates are the ones in this kernel's `security.h`. This is much stronger than a
   plausible-looking header.
2. **No `seqno`.** The task's header list mentioned `seqno`; there is no such field in
   the kernel policydb container (`grep seqno` over `ss\policydb.c`/`.h` and libsepol
   `src\policydb.c` finds nothing). The header is exactly magic/strlen/string then
   version/config/sym_num/ocon_num. `seqno` exists only in Android userspace policy
   bookkeeping, not in the on-disk policydb.
3. **Only `permissive_map` is changed; all other bytes are byte-identical.** The kernel
   reload path re-derives live SIDs by *name* (`convert_context`, `services.c:2148`), so
   a same-name policy reloads cleanly. Since no name changed, the reload should convert
   without `-EINVAL`.
4. **What my parser does NOT reproduce:** the kernel's *semantic* validators
   (`policydb_bounds_sanity_check`, per-entry type/role/class validity,
   `mls_context_isvalid`, `sidtab_map` conversion). Those cannot be validated
   host-side without the live SID table. My change is confined to a bitmap that has no
   cross-references, and type 1153 < `types.nprim` = 2676, so no semantic check is
   affected. The rest of the image is the device's own unchanged bytes. Residual risk
   is therefore low but not literally zero if the loaded kernel's blob differs from the
   host pull.
5. **The "second copy" does not exist on this host.** A recursive search of
   `[WORKSPACE]` for `*precompiled*` returns exactly one file (the
   `session_20260824` blob); `ghostlock_pocs\` has no copy, and
   `binder_uaf\session_20260913\pulled\` has only CIL text and `.so` files. Any claim
   of a second binary must be re-pulled; it cannot be cross-checked here.
6. **Highbit value is a choice** (1216 vs 1153); both load, see §3. No other freedom.
7. **This is only the byte recipe/section map.** Whether `/sys/fs/selinux/load` can be
   written at all is a separate, already-documented AVC gate
   (`POLICY_LOAD_ROUTE_20260926.md`); a correct blob does not by itself bypass it.

---

## 6. One-line summary for a device-side patcher

```
magic/version : 0xf97cff8c / 30 ; permissive_map @ 0x38, 12 B (empty).
Write @0x38: 40 00 00 00 c0 04 00 00 01 00 00 00 80 04 00 00 02 00 00 00 00 00 00 00
then continue copying from old 0x44; file grows by 12 to 989742 bytes.
```
