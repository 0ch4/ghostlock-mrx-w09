# Policy patch: single most-permissive in-memory SELinux write (MRX-W09, 4.14.116)

Host-side static analysis only. No device, no adb, no edits to existing files.
Kernel source: `[WORKSPACE]\huawei_kernel_src\Code_Opensource\kernel\security\selinux\`
Device image (link-time addresses): `[FIRMWARE]\MRX-W09\extracted\vmlinux.elf`
Exploit (read-only): `binder_uaf\session_20260922\ghostlock_mrx\ghostlock_mrx_e.c`

`policydb` link address = `0xffffff800b3b97c0` (`MRX_SYMBOLS_20260926.md:19`, re-confirmed
with `llvm-nm`: `ffffff800b3b97c0 b policydb`). All offsets below are relative to that base
and were **re-derived from the device image disassembly**, not just from headers.

---

## 0. Executive answer

- **The single most-permissive change is `policydb.permissive_map` bit `shell` (type 1153).**
  Marking the shell *source type* permissive makes `avc_denied()` grant **every class**
  (capability, file, process, mount, …) for shell-sourced decisions, because the permissive
  flag is read from the *source* context (`services.c:1119`, `services.c:1165`) and
  `avc_denied()` converts any denial into a grant when that flag is set (`avc.c:1007-1012`).
- **`policydb.allow_unknown = 1` does NOT help.** It never turns a missing
  `(shell,shell,capability)` avtab entry into an allow for a *known* class/permission. Its only
  effects are (a) an unmapped *class* → blanket `allowed = 0xffffffff`, and (b) `map_decision()`
  filling kernel bits for *permissions the kernel does not know*. The capability class and all
  its permission bits are known, so neither fires. (Detailed proof in §1.)
- **`permissive_map` needs TWO 8-byte pointer writes in general** — one to
  `permissive_map.node` (+0x1C0) pointing at a controlled fake `struct ebitmap_node`, and one to
  `permissive_map.highbit` (+0x1C8) whose value must be ≥ 1153. The zero write cannot supply a
  ≥1153 `highbit`. If the deployed policy already has `highbit ≥ 1153` **and** a node covering
  1153, one pointer write suffices. The exploit already contains this design as `--permtest`
  (`ghostlock_mrx_e.c:3883-3913`, plant at `:426-444`).
- **The avtab route is strictly worse**: it needs ≥3 writes and only affects one class/type pair.
- **commoncap still applies**: SELinux permissive/allow_unknown does **not** remove
  `cap_capable()`'s `cap_raised(cred->cap_effective, cap)` requirement (`commoncap.c:95`), and
  the capability LSM runs *before* SELinux (`security.c:210-222` break-on-first-error,
  `security.c:168` tail-insert; `capability_add_hooks` at `security.c:74`, SELinux at
  `hooks.c:6746`). You must also set `cred->cap_effective` (`cred+0x38`).
- **One tempting zero-write route is blocked**: `ss_initialized = 0` would make
  `security_compute_av()` return `allowed = 0xffffffff` (`services.c:1108-1142`), but
  `ss_initialized` lives in HKIP's write-rare region `.data_wr`
  (`__start_data_wr=0xffffff800adc0000 .. __end_data_wr=0xffffff800adc1000`; `ss_initialized`
  = `0xffffff800adc00a0`) and is only ever written via `wr_assign()` (`services.c:96-101`,
  `services.c:2092`, `hooks.c:6699`). A raw store there is expected to fault / trip HKIP.
  **Flagged as unverified-risk; do not rely on it.**

---

## 1. `allow_unknown` / `reject_unknown` — verified dead end for capability

Fields: `struct policydb` (`ss/policydb.h:237-320`), bitfields at `policydb.h:315-316`:

```c
unsigned int reject_unknown : 1;   /* bit 0 */
unsigned int allow_unknown  : 1;   /* bit 1 */
```

Layout-derived offset of the bitfield word is **+0x1DC** (see §6); bit 1 = `allow_unknown`.
Device disassembly confirms it: `security_compute_av.cfi` loads a byte at
`page+0x99C` = `policydb+0x1DC` and tests **bit 1** (`ldrb w9,[x9,#2460]; tbz w9,#1,...`).

### 1a. Normal AV computation never consults `allow_unknown`

`context_struct_compute_av()` (`ss/services.c:640-743`):

```c
655:  avd->allowed = 0;
656:  avd->auditallow = 0;
657:  avd->auditdeny = 0xffffffff;
...
677:  sattr = &policydb.type_attr_map[scontext->type - 1];
679:  tattr = &policydb.type_attr_map[tcontext->type - 1];
681:  ebitmap_for_each_positive_bit(sattr, snode, i) {
682:      ebitmap_for_each_positive_bit(tattr, tnode, j) {
685:          for (node = avtab_search_node(&policydb.te_avtab, &avkey); node; ...) {
688:              if (node->key.specified == AVTAB_ALLOWED) avd->allowed |= node->datum.u.data;
...
```

There is **no reference to `allow_unknown`** in this function. If no `(i,j,capability)`
avtab allow rule exists, `avd->allowed` stays whatever the accumulated allows were — almost
certainly `0`. A *miss* is not an *allow*.

### 1b. Where `allow_unknown` actually matters

`security_compute_av()` (`ss/services.c:1096-1143`):

```c
1108:  if (!ss_initialized) goto allow;
...
1129:  tclass = unmap_class(orig_tclass);
1130:  if (unlikely(orig_tclass && !tclass)) {      /* class not known to the kernel mapping */
1131:      if (policydb.allow_unknown) goto allow;
1132:      goto out;
1133:  }
1135:  context_struct_compute_av(scontext, tcontext, tclass, avd, xperms);
1136:  map_decision(orig_tclass, avd, policydb.allow_unknown);
...
1140: allow:
1141:  avd->allowed = 0xffffffff;
```

and `map_decision()` (`ss/services.c:239-274`):

```c
246:  for (i = 0, result = 0; i < n; i++) {
247:      if (avd->allowed & current_mapping[tclass].perms[i]) result |= 1 << i;
249:      if (allow_unknown && !current_mapping[tclass].perms[i]) result |= 1 << i;
250:  }
```

- The `goto allow` (`allowed = 0xffffffff`) only happens when `orig_tclass && !tclass`,
  i.e. the *class itself* is unmapped. `SECCLASS_CAPABILITY` **is** mapped on this device
  (`SECCLASS_CAPABILITY`/`SECCLASS_CAPABILITY2` are used at `hooks.c:1741,1744`), so this
  branch cannot fire for capability checks.
- In `map_decision()`, the `allow_unknown` clause only sets a kernel permission bit when the
  *policy permission value* `current_mapping[tclass].perms[i]` is 0 — i.e. a permission
  defined nowhere in the policy that the running kernel nonetheless knows. For the capability
  class the kernel knows all of `CAP_*`, so `perms[i]` is non-zero for every bit and line 249
  never contributes.

Device disassembly nails this down: in `security_compute_av.cfi` the *only*
`str w8,[x19]` writing `allowed = 0xffffffff` is reached after a test of the **unmapped-class**
predicate; the `allow_unknown` bit is loaded only into the `map_decision` loop
(`ubfx ...,#1,#1` at `0xffffff80087a9ca4`).

**Conclusion:** `allow_unknown = 1` (one-field patch) does not permit capability, file, or mount
operations that lack an explicit avtab allow. It is **not** a usable route. `reject_unknown`
is likewise irrelevant.

---

## 2. `policydb.permissive_map` — the correct lever

### 2a. Consulted on the SOURCE type, for every class

`security_compute_av()` (`ss/services.c:1118-1120`):

```c
1118:  /* permissive domain? */
1119:  if (ebitmap_get_bit(&policydb.permissive_map, scontext->type))
1120:      avd->flags |= AVD_FLAGS_PERMISSIVE;
```

(`security_compute_av_user()` at `ss/services.c:1164-1166` does the same; that path is only
selinuxfs, not enforcement.) There is no `policydb_type_is_permissive()` helper in this tree;
the check is inline.

`avc_has_perm_noaudit()` → on denial → `avc_denied()` (`avc.c:1116-1142`, `avc.c:999-1013`):

```c
1004:  if (flags & AVC_STRICT) return -EACCES;
1007:  if (selinux_enforcing && !(avd->flags & AVD_FLAGS_PERMISSIVE)) return -EACCES;
1010:  avc_update_node(AVC_CALLBACK_GRANT, requested, ...);
1012:  return 0;
```

On MRX-W09 `selinux_enforcing` is the compile-time constant 1
(`CONFIG_SECURITY_SELINUX_DEVELOP` is not set; `get_selinux_enforcing` is `orr w0,wzr,#1;ret`),
so the device's `avc_denied` is literally:

```
ffffff800878c7a4 <avc_denied>:
  tbnz w6,#0, +0x14          ; AVC_STRICT -> -EACCES
  ldrb w11,[x7,#16]          ; avd->flags
  tbnz w11,#0, +0x1c         ; AVD_FLAGS_PERMISSIVE -> grant
  orr  w0,wzr,#0xfffffff3    ; -EACCES
```

So setting `AVD_FLAGS_PERMISSIVE` on the source type gives a **blanket grant for all classes**,
including `SECCLASS_CAPABILITY`. Note `AVC_STRICT` (a handful of call sites) still denies — see
caveats in §5/§7.

### 2b. Exact ebitmap layout

`struct ebitmap` and node (`ss/ebitmap.h:22-46`):

```c
#define EBITMAP_NODE_SIZE 64            /* CONFIG_64BIT */
#define EBITMAP_UNIT_NUMS ((EBITMAP_NODE_SIZE - sizeof(void*) - sizeof(u32)) / sizeof(unsigned long)) /* = 6 */
#define EBITMAP_UNIT_SIZE BITS_PER_LONG /* 64 */
#define EBITMAP_SIZE (EBITMAP_UNIT_NUMS * EBITMAP_UNIT_SIZE) /* = 384 */

struct ebitmap_node { struct ebitmap_node *next; unsigned long maps[6]; u32 startbit; };
struct ebitmap      { struct ebitmap_node *node; u32 highbit; bool protectable; };
```

LP64 offsets: `ebitmap_node.next @0`, `maps @+8`, `startbit @+0x38` (56), size 64.
`ebitmap`: `node @+0`, `highbit @+8`, `protectable @+0xC`.

`policydb.permissive_map` offset **+0x1C0** (`policydb.h:308`), so:
- `.node`    @ `policydb + 0x1C0`
- `.highbit` @ `policydb + 0x1C8`

Device disassembly of `security_compute_av.cfi` (`0xffffff80087a9a4c`) confirms every one:

```
ldr w11,[x11,#2440]   ; highbit : page+0x988 -> policydb+0x1C8
ldr x11,[x11,#2432]   ; node    : page+0x980 -> policydb+0x1C0
ldr w12,[x11,#56]     ; node->startbit @ +0x38
add x13,x12,#0x180    ; startbit + 384    (EBITMAP_SIZE)
lsr w12,w10,#6 / ldr x11,[x11,#8]   ; maps[(bit-startbit)/64] @ node+8
tst x11,x10 ; b.eq
orr w10,w10,#1 ; str w10,[x19,#16]   ; avd->flags |= AVD_FLAGS_PERMISSIVE
```

### 2c. What must be true for type 1153 to read as permissive

`ebitmap_get_bit()` (`ss/ebitmap.c:261-276`):

```c
265:  if (e->highbit < bit) return 0;              /* (A) highbit must be >= 1153      */
268:  n = e->node;
269:  while (n && (n->startbit <= bit)) {
270:      if ((n->startbit + EBITMAP_SIZE) > bit)  /* (B) node must cover 1153         */
271:          return ebitmap_node_get_bit(n, bit); /* (C) maps[index] bit ofs set       */
272:      n = n->next;
273:  }
274:  return 0;
```

`ebitmap_node_get_bit()` (`ss/ebitmap.h:92-102`): `index=(bit-startbit)/64`,
`ofs=(bit-startbit)%64`, `BUG_ON(index >= 6)`, return `maps[index] & (1<<ofs)`.

So with a controlled node we need:
1. `highbit >= 1153` (or the function returns 0 before looking at any node).
2. a node with `startbit <= 1153 < startbit + 384`.
3. `maps[(1153-startbit)/64]` bit `(1153-startbit)%64` set.

**Can we point `.node` at controlled bytes?** Yes. `policydb` is an ordinary writable global in
`.bss` (objdump `-t`: `ffffff800b3b97c0 l O .bss policydb`), and `.node`/`.highbit` are plain
fields; the kernel itself writes them with ordinary stores during `ebitmap_read()`.
Redirecting `.node` to our own writable bytes avoids the fact that the *real* permissive node
would be allocated from the HKIP/prmem-protected `selinux_pool`
(`ebitmap.h:20 HISI_SELINUX_EBITMAP_RO true`; `ebitmap.c:54-61 try_alloc/pzalloc`), which a raw
store may not be allowed to modify.

The exploit already builds exactly such a node (`ghostlock_mrx_e.c:426-444`):

```
startbit = 779   (kernel type; deployed policy: kernel=779, shell=1153)
node covers 779..1162  => 1153 is at index 5, ofs 54  => maps[5] bit 54
maps[0]=~0 (type 779), maps[1]=W (side-store steer), maps[3..6]=~0 (covers 1153)
next = self|1  (must be ODD, see §7)
```

One node covering 779..1162 makes **both the kernel SID (type 779) and shell (1153)**
permissive with a single map. That is convenient but not required; a shell-only node is enough
for the question as asked.

---

## 3. The avtab route — layout and why it cannot win

`ss/avtab.h:28-91`:

```c
struct avtab_key  { u16 source_type; u16 target_type; u16 target_class; u16 specified; }; /* 8 B  */
struct avtab_datum{ union { u32 data; struct avtab_extended_perms *xperms; } u; };        /* 8 B  */
struct avtab_node { struct avtab_key key; struct avtab_datum datum; struct avtab_node *next; }; /* 24 B */
struct avtab      { struct avtab_node **htable; u32 nel; u32 nslot; u32 mask; };           /* 24 B  */
```

LP64 field offsets / device confirmation (`context_struct_compute_av.cfi`):

| item | offset | disasm evidence |
|---|---|---|
| `key.source_type` | +0 | `strh w19,[sp,#64]` |
| `key.target_type` | +2 | `strh w20,[sp,#66]` |
| `key.target_class`| +4 | `strh w19,[sp,#68]` |
| `key.specified`   | +6 | `strh w11,#0x707,[sp,#70]`, `ldrh w11,[x0,#6]` |
| `datum.u.data`    | +8 | `ldr w8,[x26,#8]` |
| `node.next`       | +16| `ldr x8,[x26,#16]` |
| `te_avtab` in policydb | +0xE8 | `add x0,x0,#0x8a8` = page+0x8A8 → +0xE8 |
| `htable` → `nel`/`nslot`/`mask` | +0/+8/+12/+16 | avtab struct |

`avtab_search_node()` (`ss/avtab.c:216-245`) requires an **exact key match** and walks
`h->htable[avtab_hash(key, h->mask)]`. Therefore:

- Writing a literal **0** into an avtab entry's `datum.u.data` can only *remove* permissions
  from an existing allow; SELinux has no "deny" entries in the type-enforcement table.
- To *create* an allow you must supply a node with the exact key `(1153,1153,SECCLASS_CAPABILITY)`
  whose `specified` includes `AVTAB_ALLOWED`, and have the bucket for the (key,mask) hash point
  at it. That needs at least: one write to `te_avtab.htable` (or the bucket slot) **plus** the
  fake node/key/datum (`avtab.h:79-83`) **plus** knowledge of the bucket index (`h->mask` is a
  policy-derived u32 at `te_avtab+0x10`). ≥3 writes.
- Even if achieved, it grants capability permissions only for the `(1153,1153)` pair — it does
  nothing for file/mount/process classes, whereas `permissive_map` grants everything.
- `context_struct_compute_av()` walks the full attribute set `sattr × tattr`
  (`services.c:677-703`), but that only widens which existing rules are OR-ed; it does not invent
  rules.

**Verdict:** the avtab route is dominated by `permissive_map` on both cost and breadth.

---

## 4. Ranked recommendation

Budget stated: (i) one 8-byte pointer write, (ii) one 8-byte zero write.

| rank | route | what to write where | why it works | caveats |
|---|---|---|---|---|
| **1** | `policydb.permissive_map` (shell type) | **two** 8-byte **pointer** writes: `<policydb>+0x1C8 ← V` (V a kernel pointer with `low32(V) ≥ 1153`, first word odd) and `<policydb>+0x1C0 ← A` (A = controlled fake node with `startbit≤1153<startbit+384` and the 1153 bit set, `next` odd) | Sets `AVD_FLAGS_PERMISSIVE` for every shell-sourced decision (`services.c:1119`) → `avc_denied()` returns 0 for every class (`avc.c:1007-1012`) | Needs 2 writes, not 1+1; the zero write cannot provide `highbit`; AVC entries cached *before* the patch keep their old `flags` (no timeout; only eviction/`avc_ss_reset` clears them — `avc.c:929-952`, `services.c:2095/2176/2788`); `AVC_STRICT` sites still deny (`avc.c:1004`) |
| 1′ | same, if deployed `permissive_map.highbit` is **already** ≥ 1153 **and** a node covers 1153 | one 8-byte pointer write: `<policydb>+0x1C0 ← A` (or write a pointer into the existing node's `maps[index]` where the 1153 bit offset is ≥32, since kernel pointers have bits 32–63 = 0xffffffff) | same as above | Depends on an unverified policy property (see §7); the *existing* node lives in prmem-protected memory, so writing into it may fault — redirecting `.node` to our own window is safer |
| 2 | `policydb.allow_unknown = 1` (bit 1 of `<policydb>+0x1DC`) | one write to set bit 1 | **Does not work** for capability/file/mount: no `context_struct_compute_av` path reads it; only unmapped classes and unknown permission bits are affected (§1) | misidentified as a "one-field allow-all"; reject as a route |
| 3 | avtab entry rewrite | `te_avtab.htable` + a key-matching fake `avtab_node` + hash bucket | grants only the one `(1153,1153,class)` pair | ≥3 writes; needs unknown bucket mask/index; narrower than permissive_map (§3) |
| — | `ss_initialized = 0` (8-byte zero) | `0xffffff800adc00a0 ← 0` | would make `security_compute_av()` return `allowed=0xffffffff` for everything (`services.c:1108-1142`) | **`ss_initialized` is in HKIP-protected write-rare `.data_wr`** (`__start_data_wr=0xffffff800adc0000`..`__end=0x…adc1000`, symbol `ss_initialized=0xffffff800adc00a0`); written only via `wr_assign()` (`services.c:96-101,2092`, `hooks.c:6699`, `prmem.h:159-166`). A raw store is expected to fault/trip HKIP. Unverified risk — flag. |

**Recommendation:** `permissive_map` (§2), with the exploit's existing `--permtest` sequence.
Treat `allow_unknown` as disproven. The "one pointer + one zero" budget is **insufficient** for
the correct route unless the deployed policy already has `highbit ≥ 1153`; in that lucky case the
single useful write is `permissive_map.node ← <controlled fake node>`.

### Important write-shape detail (from `TASK_WRITE_SHAPE_20260926.md` + `ghostlock_mrx_e.c`)

The pointer write `value=V, target=T` performs **two** stores for the shapes the exploit builds:
`*((V & ~3) + 8) = T` first, then `*(T) = V` (see `ghostlock_mrx_e.c:409-444`, and the
`__rb_change_child` disassembly in `TASK_WRITE_SHAPE_20260926.md:51-104`). Consequences:

- Writing `.highbit` (`T = +0x1C8`): the side store clobbers `V+8`. Choose `V` in our own window
  so this is harmless.
- Writing `.node` (`T = +0x1C0`, `V = A`): the side store targets `A+8` = `maps[0]`. To protect
  the coverage bit, the exploit makes `*(A+0x10) == W` (it sets `maps[1] = W = the fake waiter`),
  which diverts the store to `A+0x10 = maps[1]` (`ghostlock_mrx_e.c:431-438`). If you build a
  fresh node, either reproduce this steer or choose `startbit` so the needed bit lives in
  `maps[1]` (index 1), leaving `maps[0]` free to be clobbered.

---

## 5. Does the SELinux route also satisfy commoncap? **No.**

`cap_capable()` is a commoncap hook (`commoncap.c:121-124`, `LSM_HOOK_INIT(capable, cap_capable)`
at `commoncap.c:1325`). `security_capable()` runs the hook chain and stops at the first error
(`security.c:277-281`, `security.c:210-222`). `capability_add_hooks()` is installed from
`security_init()` at `security.c:74`, i.e. **before** `security_init()` calls
`do_security_initcalls()` at `security.c:81`, which is what runs `selinux_init()`
(`hooks.c:6685`, registered at `hooks.c:6746`); `security_add_hooks()` appends at the **tail**
(`security.c:168`). So **commoncap runs first**:

```c
/* commoncap.c:80-95 */
if (unlikely(hkip_check_uid_root())) return -EPERM;
...
if (ns == cred->user_ns)
    return cap_raised(cred->cap_effective, cap) ? 0 : -EPERM;
```

Therefore:
- `permissive_map` / `allow_unknown` **cannot** substitute for `cap_effective`. SELinux only
  matters after commoncap returns 0.
- We must also make `cap_raised(cred->cap_effective, cap)` true. `cap_effective` is a
  `kernel_cap_t` = 2×u32 at **`cred + 0x38`** (`TASK_CRED_OFFSETS_20260926.md:61,195-203`,
  confirmed in `cap_capable.cfi`: `ldr w8,[x8,#56]` with `x8 = cred + (cap>>5)*4`).
- Writing a kernel pointer `V` at `cred+0x38` sets `cap[0] = low32(V)` (caps 0–31) and
  `cap[1] = high32(V)` (caps 32–63). Because kernel addresses are `0xffffff8…`, the high word is
  `0xffffff80` → **caps 32–63 are all set for free**. Caps 0–31 come from V's low 32 bits, so
  pick V with the needed bits (e.g. `CAP_SETUID=7` → bit 7, i.e. `(V & 0x80)`; `CAP_SYS_ADMIN=21`
  → bit 21). This is exactly why the exploit's `g_blackval` selection requires `a & 0x80`
  (`ghostlock_mrx_e.c:486-508`).
- **HKIP caveat (strong):** `__cap_capable()` calls `hkip_check_uid_root()` *before* testing
  `cap_effective` (`commoncap.c:85-86`; device `cap_capable.cfi @0xffffff800877fc20` calls
  `hkip_check_uid_root.cfi` first and returns `-EPERM` if non-zero). If our task is tracked by
  HKIP (`task+0x820` nonzero and the uid-root bit clear) capabilities may be denied regardless
  of `cap_effective`. **Uncertain; flag and validate on-device.**

`cap_setuid`-style operations additionally go through `cap_task_fix_setuid`
(`commoncap.c` hook table `:1337`) and (if using `init_cred`) would flip us to the kernel SID —
explicitly off the table per the task. Staying in `u:r:shell:s0` and setting `cap_effective` is
the intended path.

---

## 6. Offset derivations (so the numbers are auditable)

`struct policydb` (`ss/policydb.h:237-320`) replicated with LP64 rules and compiled; matched to
the device image disassembly:

| field | offset | independent device check |
|---|---|---|
| `mls_enabled` | 0x00 | |
| `symtab[8]` | 0x08 | `p_classes.nprim` @ page+0x7E0 → +0x20 = `symtab[1].nprim` |
| `sym_val_to_name[8]` | 0x88 | |
| `class_val_to_struct` | 0xC8 | `add x8,x8,#0x888` = page+0x888 |
| `role_val_to_struct` | 0xD0 | |
| `user_val_to_struct` | 0xD8 | |
| `type_val_to_struct` | 0xE0 | |
| `te_avtab` | 0xE8 | `add x0,x0,#0x8a8` for `avtab_search_node` |
| `filename_trans_ttypes` | 0x108 | |
| `te_cond_avtab` | 0x128 | |
| `ocontexts[9]` | 0x150 | |
| `range_tr` | 0x1A0 | |
| `type_attr_map` | 0x1A8 | `ldr x8,[x8,#224]` (x8=page+0x888) = page+0x968 |
| `policycaps` | 0x1B0 | |
| **`permissive_map`** | **0x1C0** | `ldr x11,[x11,#2432]`; `highbit` `ldr w11,[x11,#2440]` |
| `len` | 0x1D0 | |
| `policyvers` | 0x1D8 | |
| `reject_unknown:1` / `allow_unknown:1` | **0x1DC** (bit0/bit1) | `ldrb w9,[x9,#2460]` (2460=0x99C) + `ubfx #1,#1` |
| `process_class` / `process_trans_perms` | 0x1E0 / 0x1E4 | |

`sizeof(struct policydb)` = 0x1E8 (488).

Protected regions (from `objdump -t` / `llvm-nm`):
`__start_data_wr=0xffffff800adc0000`, `__end_data_wr=0xffffff800adc1000`,
`__start_data_wr_after_init=0xffffff800adc1000..0x…adc2000`,
`__start_data_rw=0x…adc2000..0x…adc3000`. `ss_initialized=0xffffff800adc00a0` is inside
`data_wr`; `policydb=0xffffff800b3b97c0` is in ordinary `.bss` (writable).

---

## 7. Recommended next experiment (single, concrete)

Reuse the exploit's existing `--permtest` path (`ghostlock_mrx_e.c:3883-3913`), which is the
`permissive_map` installation + an SELinux-only oracle:

**Prepare (free, in the stamped window at `window_base = W-0x78`):** build the fake
`struct ebitmap_node` at `window_base + 0xC8` (`ghostlock_mrx_e.c:426-444`):
`next = (window_base+0xC8)|1`, `maps[0]=~0`, `maps[1]=W` (side-store steer),
`maps[2..5]=~0`, `startbit = 779` (covers type 1153 at index 5 ofs 54, and kernel type 779 at
index 0 ofs 0).

**Writes (two 8-byte pointer writes, highbit first):**

1. **target** `= policydb(g_slide) + 0x1C8`, **value** `= g_blackval`
   (= `window_base + 0xB8`, a window slot whose first word is odd and whose `low32` is large)
   → `permissive_map.highbit = low32(g_blackval) ≥ 1153`.
   (`ghostlock_mrx_e.c:3901`)
2. **target** `= policydb(g_slide) + 0x1C0`, **value** `= g_perm_node`
   (= `window_base + 0xC8`, the fake node address)
   → `permissive_map.node = <fake node>`.
   (`ghostlock_mrx_e.c:3902`)

Do the install(s) **before** exercising the oracle, and only then perform a single check on an
uncached `(sid,sid,class)` tuple (a cached pre-patch denial has `flags=0` and will still deny;
`ghostlock_mrx_e.c:3891-3894`).

**Observe:**
- Primary oracle: `open("/proc/self/attr/exec", O_WRONLY)` then
  `write(fd, "u:r:shell:s0", 13)`. This path is DAC-legal and was measured to fail **only**
  because of SELinux (`ghostlock_mrx_e.c:3905-3911`). Baseline shell = `-1/EACCES`;
  `write(...) >= 0` ⇒ the shell source type is permissive.
- Secondary: `capset(NULL, zeros)` returns 0 for a permissive source even without caps, because
  dropping all capabilities is DAC/commoncap-legal (`ghostlock_mrx_e.c:3884-3886`).
- Then re-test `mount` / `open("/dev/block/...")` on **fresh** target SIDs (new AVC tuples) to
  confirm cross-class breadth.

**If the oracle still returns EACCES:** the likely causes, in order, are
(a) `highbit` write did not land (`g_blackval` low32 < 1153 or side store mis-steered),
(b) the fake node's 1153 bit is not where expected (`startbit`/`maps` mismatch),
(c) the AVC tuple was already cached from a prior denial — retry with a different target/class.

**Do not** spend the zero write on the SELinux policy; there is no validated zero-write target
that grants permissions (`ss_initialized` is HKIP-protected, avtab zeroing only removes bits).
Reserve any additional write for `cred+0x38` (`cap_effective`), which is mandatory (§5).

---

## 8. Uncertainty / flags

1. **Deployed `permissive_map` content is not known statically here.** The shipped policy could
   not be located in `[FIRMWARE]\MRX-W09\extracted` (no `sepolicy` / `precompiled_sepolicy`).
   Whether `highbit` is already ≥ 1153 (1 write suffice) or 0 (2 writes required) is unverified.
   The exploit's own design assumes 2 writes.
2. **`.data_wr` writability.** The deduction that `ss_initialized` is RO is from the
   `wr_assign`/`hkip_write_rowm_*` machinery and the section-symbol ranges; I did not verify the
   PTE permission state. Treat "zero `ss_initialized`" as unproven.
3. **HKIP `hkip_check_uid_root`.** It gates `cap_capable` before `cap_effective`
   (`commoncap.c:85-86`). Whether our shell task trips it is a device/runtime property; if it
   does, even a correct `cap_effective` write will not grant capabilities.
4. **AVC cache staleness.** No timeout; pre-patch denied tuples keep `flags=0`. New tuples are
   computed fresh and will observe the new `permissive_map`. `avc_ss_reset()` is only reachable
   via policy load / boolean changes (`services.c:2095,2176,2788`, `selinuxfs.c:155`), which we
   do not have.
5. **`AVC_STRICT`.** A small number of `avc_has_perm_flags(..., AVC_STRICT)` callers bypass the
   permissive grant entirely (`avc.c:1004`). The mount/open/attr paths relevant here use the
   normal `avc_has_perm()` path.
6. **Offset confidence is high** for `permissive_map`, `allow_unknown`, `te_avtab`,
   `type_attr_map`, `class_val_to_struct`, and `ebitmap_node`: each was cross-checked against the
   device image disassembly, not only the header math.
