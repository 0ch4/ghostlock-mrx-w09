# GhostLock MRX-W09 — single best breakthrough to full privileged root (2026-09-26)

Host-side analysis only. No adb, no device, no existing files modified. This is the
only file created.

Target of record: **Huawei MRX-W09**, Kirin 990, arm64, Linux **4.14.116**, EMUI 11,
SELinux enforcing + HKIP/HHEE, `LTO_CLANG=y` + `CFI_CLANG=y`, `CONFIG_DEBUG_SPINLOCK=y`,
`CONFIG_PREEMPT=y`, `CONFIG_STRICT_KERNEL_RWX=y`, `CONFIG_LOCKDEP` **not set**,
`CONFIG_PROVE_LOCKING` not set, `CONFIG_SECURITY_SELINUX_DEVELOP` not set,
`CONFIG_DEBUG_CREDENTIALS` not set.

Everything below was re-derived from the device image
(`[FIRMWARE]\MRX-W09\extracted\vmlinux.elf`), the shipped Huawei source tree
(`[WORKSPACE]\huawei_kernel_src\Code_Opensource\kernel`), the exploit source
(`binder_uaf\session_20260922\ghostlock_mrx\ghostlock_mrx_e.c`, read-only), and the
corpus (`ghostlock_pocs\`, ~100 ports).

---

## 0. Verified state and the one fact that changes the answer

Already proven on-device (do not re-litigate):

* arbitrary 8-byte pointer write `*(target) = V` where `V` points at an odd word
  (`*(u64*)V & 1`), plus a side store `*((V & ~3)+8) = target`
  (`TASK_WRITE_SHAPE_20260926.md:100-137`; `FACTS 9h`, `9r`);
* LEAF zero write `*(target) = 0` via `value = target-8`
  (`TASK_WRITE_SHAPE_20260926.md:143-160`);
* boot_id 16-byte read, re-armable multi-walk (`FACTS 9al(1)`: `--rearmN 6` ⇒ 5/6);
* a task with **uid 0 in `u:r:shell:s0`** that can write `/data/local/tmp`
  (`ghostlock_mrx_e.c:3947-4096`, `--simple`), with the HKIP shield by
  `task->pid = 0` (`TASK_PID0_RISK_20260926.md:17,58-67`);
* the shell source type (1153) can be made **permissive in memory** by repointing
  `policydb.permissive_map` (`COMPLETE_ROOT_PLAN.md:19-34`,
  `TASK_POLICY_PATCH_20260926.md:190-228`);
* **`cred->cap_effective` has already been written through this primitive and landed**:
  `FACTS 9al(2)` — `--endgame3 … capget -> eff=0xffffffebf2e1fc90 CAP_SETUID=1`.
  The stored pointer's **low 32 bits became `cap_effective[0]`**.

The fact the parent session has not exploited: **`cap_effective` is not a value you must
synthesise from small integers. It is 8 bytes, and a pointer write deposits
`{cap[0]=low32(V), cap[1]=high32(V)}`. For any kernel address `high32(V)=0xffffff80`, and
you are free to *choose* `V` among many writable kernel addresses. So the capability mask
is selected, not encoded.** `TASK_POLICY_PATCH_20260926.md:353-358` already states this
("caps 0–31 come from V's low 32 bits … pick V with the needed bits"), but the corpus
only ever required bit 7 (`CAP_SETUID`) in `g_blackval`
(`ghostlock_mrx_e.c:486-508`). Requiring bit 21 instead is the whole breakthrough.

For Linux 4.14: `cap_capable()` tests `cred->cap_effective[cap>>5]` bit `cap&31`
(`TASK_CRED_OFFSETS_20260926.md:61`), i.e. word 0 at `cred+0x38` for `CAP_SYS_ADMIN`.
`mount` → `capable(CAP_SYS_ADMIN)` → `security_capable` → `cap_capable`; the HKIP gate in
front of it is bypassed while `task->pid == 0`
(`TASK_POLICY_PATCH_20260926.md:339-345`, `TASK_PID0_RISK_20260926.md:58-67`), and the
SELinux gate is already permissive for the shell source type. So one pointer write with
bit21 in its low word is sufficient to `mount`.

---

## 1. Ranked table

| # | route | needed primitive | # writes (primitive) | yields | blockers |
|---|-------|------------------|----------------------|--------|----------|
| **1** | **Address-selected `cap_effective` write (RECOMMENDED)** — write `V` with `low32(V)` = desired cap mask into `cred+0x38`, choosing `V` from a stamped window whose stack VA has the bits, or from a static writable candidate | 1 pointer write (value chosen for its low32) | **1** (+ shield/identity writes already done) | `cap[0]=low32(V)` → **CAP_SYS_ADMIN(21), CAP_DAC_OVERRIDE(1), CAP_FOWNER(3), CAP_MKNOD(27)** … plus `cap[1]=0xffffff80`. `mount`, `/dev/block`, tmpfs+setuid-root closure | bit21 is a property of the chosen `V`, not freely writable: must pick/seek an address with it (≈50 % per arm; arm-level selection, see §2). Cannot get a cap whose bit is absent from every available address (bits 9–20 and 28–30 partly luck). |
| 2 | **Kernel-type permissive + proven cede/fork** (route A) | 2 pointer writes (permissive_map `.highbit`,`.node`) + 2 pointer writes (cede `real_cred`/`cred` to `&init_cred`) | 4 | **uid 0 + FULL CAPS + kernel SID + own HKIP bit**, and with kernel type permissive the old "kernel domain denies writes/exec" objection disappears; enables `core_pattern` pipe helpers | permissive node must be selected/persisted correctly (off-by-one between `type_attr_map` bit index and `permissive_map` bit index, §5.1); AVC cache may hold pre-patch denials; cede fights the `*(&init_cred)&1` gate (`FACTS 9an(2)` vs `CEDE_LANDED_20260924.md:22`) — verify first. |
| 3 | **UMH via forged `work_struct`/`subprocess_info`** | **full kernel RW**, not pointer+zero | ≥5 impossible writes | kernel execs helper as root, full caps | **Impossible with this primitive**: the 2 worklist splices need `*(fake_entry)&1` where `entry.next` must be an even list head; 3 counter increments are small-int writes; `work.func` is a text pointer whose side store hits RO text (`STRICT_KERNEL_RWX=y`). §3. |
| 4 | **ashmem fops hijack → full RW** | pointer write (Phase A, landed) **+ a persistent controlled kernel buffer + text-pointer writes** | Phase A 1; Phase B ≥10 | arbitrary kernel RW → full cred patch / UMH | **Blocked**: no persistent controlled buffer at a known address; the fake table can only live in the transient stamped window (and the window's shallow half is clobbered by `do_ip_setsockopt`'s own frame, `FACTS 9ag`); text pointers cannot be written by the primitive. §4. |
| 5 | `core_pattern` / `modprobe_path` pipe helper | **only a userspace `write()`** (uid 0 + permissive already) | 0 | kernel spawns helper with root full caps | helper is exec'd by the **kernel** SELinux domain; denied unless the kernel type is permissive (route 2) or the helper lives on a kernel-executable type. Zero primitive writes, but it is an *amplifier of route 2*, not a standalone breakthrough. §5.4 |
| 6 | `cred->security := *(init_cred+0x78)` (real kernel tsec) | 1 pointer write + 1 destructive read | 1 | kernel SID (then route 2/5) | read is destructive (`FINAL_STATE_20260924.md:22-27`); alone it yields kernel SID, still blocked without kernel-permissive. |
| 7 | `fork-storm` (`copy_process`→`hkip_init_task`) | cede write | 1 | child born legal root | needs the cede route (2); no extra power over route 2. |
| — | `selinux_state.enforcing := 0` | — | — | — | **impossible**: compile-time constant; `avc_denied` reads no global (`TASK_POLICY_PATCH_20260926.md:157-167`). |
| — | `security_hook_heads.capable` | — | — | — | **impossible**: `__ro_after_init` + `STRICT_KERNEL_RWX` (`FACTS` §3; `TASK_POLICY_PATCH_20260926.md:329-345`). |
| — | avtab allow injection | ≥3 | narrow | dominated by permissive_map (`TASK_POLICY_PATCH_20260926.md:252-292`). |

**Recommendation: route 1.** It is the cheapest (one extra write), it is already
demonstrated to land (`FACTS 9al(2)`), it directly attacks the named blocker
(bit 21), and it composes into full root through a non-`nosuid` tmpfs + setuid binary.
Routes 2/5 are the path to *full* (all-bit) capabilities if the subset is insufficient.

---

## 2. Recommended route — address-selected `cap_effective` injection

### 2.1 The mechanism, exactly

`cap_effective` is `kernel_cap_t = u32 cap[2]` at **`cred + 0x38`**
(`TASK_CRED_OFFSETS_20260926.md:61,195-203`). A pointer write `*(cred+0x38) = V`
stores `V` as the 8-byte value, so:

```
cap_effective[0] (caps  0..31) = low32(V)
cap_effective[1] (caps 32..63) = high32(V) = 0xffffff80   (any kernel text/data VA)
```

`cap_capable()` computes `word = cap>>5`, `bit = 1<<(cap&31)`, and tests
`cred->cap_effective[word]` (`TASK_CRED_OFFSETS_20260926.md:108-111`). Therefore:

* `CAP_SYS_ADMIN` (21) needs `low32(V) & 0x200000`;
* `CAP_DAC_OVERRIDE` (1) `0x2`; `CAP_FOWNER` (3) `0x8`; `CAP_FSETID` (4) `0x10`;
  `CAP_KILL` (5) `0x20`; `CAP_SETGID` (6) `0x40`; `CAP_SETUID` (7) `0x80`;
  `CAP_MKNOD` (27) `0x08000000`.

There is **no capability above 31 that matters** on 4.14 (`CAP_LAST_CAP = 39`, so
`cap[1]` only matters for bits 32–39, which `0xffffff80` does **not** cover — bits 0–6 of
`cap[1]` are zero; the classic 0–31 caps are all in `cap[0]`). So the entire game is
`low32(V)`.

### 2.2 Candidate address class A — the stamped window (primary)

The window geometry is fixed: `window_base = W - 0x78`, fake `rt_mutex` at
`window_base + 0x48`, waiter at `W` (`FACTS 9e`/`9h`, `ghostlock_mrx_e.c:390-508`).
`W` is leaked (`g_waiter_abs`). Any 8-aligned slot `A = window_base + off`, `off ∈ [0,0xF8]`,
is a valid value address if we place an odd qword there: `build_v2()` already does exactly
that — it scans a candidate list `ks[]`, writes `1` at each slot, and keeps the first whose
address has bit 7 (`ghostlock_mrx_e.c:488-508`).

Crucial simplification: for `off < 0x100`, `bit21(A) = bit21(window_base)` except for a
carry chain of probability ≈ 2⁻¹³. **bit21 is therefore an arm-level property**: pick a
`y`-thread whose stack VA has bit 21, then every slot works.

Runtime selection algorithm:

```
for (;;) {
    arm();                                  /* new y-thread, fresh kernel stack */
    if (!(g_waiter_abs >= 0xffffff8000000000ULL)) continue;
    uint64_t base = g_waiter_abs - 0x78;
    if (!(base & 0x200000ULL)) continue;    /* want CAP_SYS_ADMIN; ~50% of arms */
    /* optional: also want more bits; check base & 0x0b0000ff etc. */
    int off = pick_slot_that_does_not_collide();  /* e.g. 0x18..0x40, or 0xC8.. */
    *(u64*)(g_sbuf + off) = 1;              /* make *(A)&1 odd (gate) */
    A = base + off;
    break;
}
/* single write */
arm_write_inproc(A, cred + 0x38, 0);        /* *(cred+0x38) = A */
```

`arm_write_inproc` is the proven stamp+trigger write; it already returns a success code and
`--endgame3` proved this exact shape lands (`FACTS 9al(2)`). The side store writes
`cred+0x38` into `A+8`, which is **inside our own window** (safe; the design rule of
`FACTS 9r`).

Expected cost: ≈1 write, ≈2 arms (geometric, p(success)=~0.5 per arm). Re-arming is proven
5/6 (`FACTS 9al(1)`; the per-process multi-walk limit was broken by the re-armable
stamper).

### 2.3 Candidate address class B — static writable `.data` address (fallback, no re-arm luck)

If re-arming is undesirable, select a **static** writable kernel address `A` such that
`(A & 1 word content)` is odd and `A+8` is harmless padding. Because `A = link + g_slide`
and we know `g_slide`, precompute a list of candidates and pick at runtime the one whose
`(A & 0x200000)` (and any other desired bits) is set. Since `bit21` is set for roughly half
of the image's `.data` low32 range, a list of 30–50 candidates makes this deterministic.

The 8-byte word at `A` must be odd **at runtime**. `.bss` is zero → unusable. `.data`
integer/flag globals are usable; pointer globals are aligned (even) → unusable. Host-side
candidate generation (read-only):

```powershell
$img = '[FIRMWARE]\MRX-W09\extracted\vmlinux.elf'
$nm  = '[WORKSPACE]\android-ndk-r20b\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-nm.exe'
& $nm -n $img | findstr ' [dD] '        # symbols in the writable data section
# for each candidate address A: read the 8 bytes at A from the ELF, keep A where
# (word & 1) && ((A + slide) & 0x200000) for the (small) set of possible slides,
# and where the bytes at A+8 are padding (no symbol range covers A+8).
```

The side store writes `cred+0x38` into `A+8`; only choose candidates where `A+8` is
inter-symbol padding. (`--storetest` already writes a window pointer into
`sysctl_perf_event_paranoid`, proving arbitrary `.data` targets are writable —
`FACTS 9h`.)

### 2.4 Oracle and closure to full privileged root

1. **cap oracle (no device side effect):**
   `capget({_LINUX_CAPABILITY_VERSION_3, pid=getuid()}, data)`; expect `data[0].effective`
   bit 21 set. (`FACTS 9al(2)` used exactly `capget` and saw the low32 of the written
   pointer appear.)
2. **mount oracle (what we actually need):** the probe already exists at
   `ghostlock_mrx_e.c:2665`:
   `mount("tmpfs", "/data/local/tmp/glmnt", "tmpfs", 0, "mode=0777")` → 0 iff
   `CAP_SYS_ADMIN` effective and SELinux permissive (both true now).
3. **full-cap closure (persistent):** a fresh tmpfs mount carries no `MS_NOSUID`
   (unlike `/data`, `/cache`, `/splash2`, `TASK_PERSISTENCE_20260926.md:208-228`). Put a
   setuid binary there:
   ```
   mount("tmpfs", "/mnt/gl", "tmpfs", 0, "mode=0777");   // CAP_SYS_ADMIN
   cp /system/bin/sh /mnt/gl/rsh ; chmod("/mnt/gl/rsh", 04755);
   ```
   On exec of a setuid-root binary with `SECURE_NOROOT` clear, 4.14 `cap_bprm_set_creds`
   raises `cap_permitted/effective` to full for euid 0 — a genuine full-cap root process
   for any caller. SELinux is permissive for the shell source type.
4. If the shared cred is written **before** the shielded task forks, the fork's child gets
   its own HKIP bit via `copy_process → hkip_init_task` **and** inherits the cap-edited
   cred (`FINAL_STATE_20260924.md:14-17`), i.e. a legal, exitable, cap-holding root task.

---

## 3. Route 1 (UMH) — exact 4.14 layouts and why it is impossible with this primitive

### 3.1 Layouts (verified)

`CONFIG_LOCKDEP` is **not set**, so in this build (`include/linux/workqueue.h`,
`kernel/workqueue_internal.h`):

```
struct work_struct {                 /* size 0x20 */
    atomic_long_t data;              /* +0x00 */
    struct list_head entry;          /* +0x08 (next +0x08, prev +0x10) */
    work_func_t func;                /* +0x18 */
};
struct subprocess_info {             /* size 0x60  (include/linux/umh.h) */
    struct work_struct work;         /* +0x00 */
    struct completion *complete;     /* +0x20 */
    const char *path;                /* +0x28 */
    char **argv;                     /* +0x30 */
    char **envp;                     /* +0x38 */
    int wait;                        /* +0x40 */
    int retval;                      /* +0x44 */
    int (*init)(...);                /* +0x48 */
    void (*cleanup)(...);            /* +0x50 */
    void *data;                      /* +0x58 */
};
struct delayed_work { struct work_struct work; struct timer_list timer; ... };
```

Confirmed from the device image, `call_usermodehelper_exec_work.cfi = 0xffffff800819571c`:
`ldrb w8,[x0,#64]` (=`wait` @0x40), `str w0,[x19,#68]` (=`retval` @0x44),
`ldr x8,[x19,#80]` (=`cleanup` @0x50).

Workqueue internals for **this** build (`CONFIG_DEBUG_SPINLOCK=y` makes `spinlock_t` 0x18;
`CONFIG_MUTEX_SPIN_ON_OWNER=y`, `CONFIG_SYSFS=y`):

```
struct pool_workqueue {              /* kernel/workqueue.c */
    struct worker_pool *pool;        /* +0x00 */
    struct workqueue_struct *wq;     /* +0x08 */
    int work_color;                  /* +0x10 */
    int flush_color;                 /* +0x14 */
    int refcnt;                      /* +0x18 */
    int nr_in_flight[16];            /* +0x1c .. 0x5b   (WORK_NR_COLORS=16) */
    int nr_active;                   /* +0x5c */
    int max_active;                  /* +0x60 */
    struct list_head delayed_works;  /* +0x68 */
    ...
};
struct worker_pool {                 /* kernel/workqueue.c */
    spinlock_t lock;                 /* +0x00 (0x18) */
    int cpu, node, id;               /* +0x18,+0x1c,+0x20 */
    unsigned int flags;              /* +0x24 */
    unsigned long watchdog_ts;       /* +0x28 */
    struct list_head worklist;       /* +0x30 */
    int nr_workers;                  /* +0x40 */
    int nr_idle;                     /* +0x44 */
    ...
};
struct workqueue_struct {
    ... struct pool_workqueue *dfl_pwq;   /* ≈ +0xb8  (a17's 0xb0 is a 6.x layout) */
    ...
};
```

Symbols (link-time, add `g_slide`): `call_usermodehelper_exec_work.cfi`
`0xffffff800819571c` (`FACTS` §5), `system_unbound_wq` data symbol
`0xffffff800add9f30`, `system_wq` `0xffffff800add9f28` (`llvm-nm -n`). The a17 recipe
(`ghostlock-a17/src/core/umh_root.c:24-51,137-329`) uses the 6.x offsets
`WQ_DFL_PWQ_OFF 0xb0 / PWQ_NR_ACTIVE 0x5c / POOL_WORKLIST 0x28 / POOL_NR_IDLE 0x3c`;
on this 4.14 build the pool/worklist offsets differ (`worklist +0x30`, `nr_idle +0x44`)
and **must** be re-measured.

### 3.2 Write count and why every hard part is impossible

The A17/ZFOLD4/A36 implementations need full kernel RW
(`ghostlock-a17/src/core/umh_root.c:137-329`, `CVE-2026-43499-ZFOLD4/src/root.c:132-308`,
`CVE-2026-43499-A36/src/root.c:131-305`; `ENDGAME_TECHNIQUES_20260923.md:198-211`). Split
into what the copy can carry vs what the primitive must write:

| item | how | possible? |
|---|---|---|
| `work.func = call_usermodehelper_exec_work` | bytes in `g_sbuf` (MCAST carries arbitrary bytes) | yes — but **only** as copy bytes |
| `work.data = pwq \| color<<4 \| 5` | copy bytes (small integer) | yes — as copy bytes |
| `path/argv/envp/complete` pointers + strings | copy bytes | yes |
| splice `pool.worklist.next/prev = &fake.entry` | primitive pointer write, `value = fake_entry` | **NO** — the gate needs `*(fake_entry)&1`, but `*(fake_entry) = entry.next` must equal the even list head. |
| `nr_in_flight[color]++`, `nr_active++`, `refcnt++` | primitive | **NO** — small integers, primitive writes only pointers/0. |
| `wake_up_worker` | PTY alloc | yes (userspace) |

Even ignoring the splice gate, writing any **text pointer** with the primitive is
impossible: the value `V` would be a text address, and the erase's side store writes
`target` into `(V&~3)+8`, which is `.text` (RO under `CONFIG_STRICT_KERNEL_RWX=y`) → a
permission fault. `TASK_WRITE_SHAPE_20260926.md:51-104` shows the side store is
unconditional for `V != 0` (`__rb_change_child`), and `FACTS 9r` shows it reboots the box
when `V` is a global.

**Verdict:** UMH is not a competitor to routes 1/2; it is a *payload* that requires full
arbitrary RW first (which route 2 cannot provide either, see §4). The `core_pattern` pipe
route (§5.4) achieves the same "kernel spawns a full-cap helper" outcome with **zero**
primitive writes, but needs the kernel SELinux type permissive (route 2).

---

## 4. Route 2 (ashmem fops → full RW) — Phase A done, Phase B blocked

* Phase A is implemented and measured: `*(ashmem_misc.fops) = window_base`
  (`ghostlock_mrx_e.c:3922-3945`; `ashmem_misc.fops = 0xffffff800b1188a8+g_slide`,
  `MRX_SYMBOLS_20260926.md:20`). The write lands because `value = window_base` is a
  writable address with an odd first word (`g_sidmode` sets `g_sbuf[0]=1`).
* The fake table and its exact field offsets are specified in
  `TASK_FILE_OPS_20260926.md:66-178` (`.read=configfs_read_bin_file` +0x10,
  `.write=configfs_write_bin_file` +0x18, etc.; `STRICT_KERNEL_RWX`, so only the plain
  symbols' bodies matter).
* **Phase B is blocked on three independent facts:**
  1. The table needs 0xf0 bytes of *persistent, attacker-controlled, known-address* kernel
     memory. The only such buffer is the stamped window. The window base coincides with
     the fake `rt_mutex` (`g_lk_off=0x48`) and waiter (`g_w_off=0x78`), and its shallow
     half (`0x00..0x40`) is overwritten by `do_ip_setsockopt`'s own frame
     (`FACTS 9ag`: buffer `0x38`/`0x68` measured clobbered; only the deep half survives).
     The OPPO port works because it has a persistent controlled page (`page_base`,
     `GhostLock-OPPO-PCKM00/exploit/src/fops.c:108,215`); we do not.
  2. The table's function pointers are **text addresses**; they can only be supplied as
     bytes by the MCAST copy, never by the primitive (side store → RO text).
  3. `ashmem_misc.fops` is a global: once the stamper returns, it points at a dead stack
     page → the next `/dev/ashmem` open dereferences stale stack (panic).

The pselect6 "blocking carrier" that was supposed to keep the window resident was
measured **not** to reach the window on this build (`FACTS 9o.2`, `9ae`), so it cannot
reliably host the table either. **Route 2 is not cheaper than route 1; it is currently
unreachable.**

---

## 5. Route 3/4 — other findings and the kernel-permissive amplifier

### 5.1 Kernel-type permissive (route A / 2–5 in the table)

The cede path is proven to yield **uid 0 + full caps + kernel SID + own HKIP bit**
(`FINAL_STATE_20260924.md:11-17`, `CEDE_LANDED_20260924.md:15-24`,
`ghostlock_mrx_e.c:4084-4091`). The parent calls it "useless" because the kernel domain
cannot write/exec (`ghostlock_mrx_e.c:4024`). That is only true while the **kernel** source
type is denied. `avc_denied` grants whenever `AVD_FLAGS_PERMISSIVE` is set, and
`security_compute_av` sets it from `permissive_map` keyed on the **source** type
(`services.c:1119`, confirmed in the shipped tree). So marking the kernel type permissive
makes the ceded child a complete root.

Uncertainty that must be measured, not assumed:

* **Off-by-one.** `permissive_map` is queried with `scontext->type` (1-based type value,
  `services.c:1119`), while `type_attr_map` is indexed `scontext->type-1` and its self bit
  is set at index `i` (`services.c:677`, `policydb.c:2530`). So a node taken from
  `type_attr_map[T-1]` carries the bit for type `T` at **bit index `T-1`**, not `T`.
  The `--permtest` code instead builds a **fake** node with `startbit=779` and
  `maps[0..5]=~0` explicitly to make **kernel type 779** permissive
  (`ghostlock_mrx_e.c:426-444`) — that is the reliable shape, but it lives in the transient
  window (the reason `--permtest` selects the blocking `g_selstamp`). A *real* node must be
  chosen only after verifying its bit index and `startbit` on-device.
* **AVC cache.** Pre-patch denials are cached with `flags=0` and there is no timeout
  (`TASK_POLICY_PATCH_20260926.md:302,468-471`). Install before the kernel-domain
  operation; a fresh boot and an untouched target class/tuple (e.g. first kernel write of
  `shell_data_file`) is the cleanest.

### 5.2 `/mnt/hisee_fs` (zero-new-write candidate)

`TASK_PERSISTENCE_20260926.md:208-234`: `/mnt/hisee_fs` is the **only** rw mount without
`nosuid`/`noexec`. Historically shell had no SELinux access; with shell permissive that
denial is lifted, and DAC is satisfied by uid 0 + (with route 1) `CAP_DAC_OVERRIDE`. If it
is really mounted rw and executable, a 4755 binary there yields full-cap root **without any
cap write at all**. Worth one on-device probe, but the runtime mount flags were never
observed (same report, §8), and the file type may trigger a non-permissive domain
transition — treat as a bonus, not the plan.

### 5.3 `core_pattern` pipe helper (amplifier)

With uid 0 + permissive shell you can already `write()` `/proc/sys/kernel/core_pattern`
(0644, no capability check) to `|/path/helper`. The helper is then `kernel_execve`'d by the
**kernel** SELinux domain, so it is denied unless the kernel type is permissive (route 2)
or the helper lives on a kernel-executable type. Combining route 2 + core_pattern is the
cleanest way to obtain a **full-cap** root process (the helper runs with kernel/init creds),
and it consumes **0** primitive writes.

### 5.4 Why the full-RW corpus ports do not apply

`tcp-zerocopy-sm`, `IonStack_S21/S22/S22U`, `CVE-2026-43499-root-KernelSU`,
`pixel-ksu-root`, `KSuRoot` all patch `cred` with a **byte/64-bit** write primitive
(e.g. `CVE-2026-43499-root-KernelSU/src/root.c:229-259` writes `CAP_FULL` to
`cred+CRED_CAPS_OFF`; `pixel-ksu-root/cves/lib/root/cred.c:21`), supplied by a pipe/physrw
primitive or a full-RW bootstrap. They do not solve our pointer-only limitation; they
confirm that the *only* general fix is full RW, which §4 shows we cannot bootstrap.

---

## 6. Explicit uncertainties / impossible things

* **Primitive gate semantics.** The corpus is internally inconsistent: the task states the
  gate is `*(u64*)V & 1` (which the exploit honours by writing `1` at the value address,
  `ghostlock_mrx_e.c:486-508`,`fops` at `:3925`), but `FACTS 9an(2)` claims ceding
  `&init_cred` (usage=4, even) is impossible, while `CEDE_LANDED_20260924.md:22` and
  `FINAL_STATE_20260924.md:14-17` report the cede landing. **Measure this first** (§7.1);
  route 1 only needs the window form (odd content we control), so it is unaffected either
  way.
* **`cap[1] = 0xffffff80` does not include caps 32–38** (bits 0–6 zero). Irrelevant for
  `CAP_SYS_ADMIN`/`CAP_SYS_MODULE`/`CAP_SYS_RAWIO`/`CAP_MKNOD` (all < 32), but note
  `CAP_SYSLOG(34)` etc. are not granted by the high word.
* **Route 1 cannot yield a cap whose bit is absent from every candidate address's
  low32.** Bits 9–20 and 28–30 are not addressable by slot offsets (only bits 0–8 are, via
  `off`), so they depend on the selected arm/static candidate. bit21 and bit27 are
  reachable; full 0xffffffff is not. If CAP_SYS_MODULE/RAWIO must be *guaranteed*, use
  route 2 (kernel permissive + cede gives `init_cred`'s `CAP_FULL_SET`).
* **Route 2's kernel node selection / AVC staleness** (§5.1) is unverified statically.
* **`STRICT_KERNEL_RWX=y`** permanently forbids primitive writes whose value is a text or
  rodata address (side store faults) — this kills UMH `work.func` writes, fake-fops text
  pointers, and any "point a global at an existing table" trick.
* **`CONFIG_SLAB`/`SLUB_DEBUG`** makes LEAF-zero on a live slab object unsafe
  (`FAKE_CRED_ROUTE_20260924.md:8`), so cred identity is edited by pointer writes, not
  zero writes.
* **pid 0 must never exit** (`TASK_PID0_RISK_20260926.md:112-136`): do the cap write on a
  shielded task and fork a legal child, or the shield task must park forever.

---

## 7. What to measure first (ordered, cheap → decisive)

1. **Gate + landing sanity (≈1 run).** Write `cred->cap_effective = A` with a known window
   `A` (bit7 only, the existing `--endgame3` shape) and print `low32(A)` plus `capget`.
   Expect `CapEff[0] == low32(A)`. This re-confirms `FACTS 9al(2)` and tells us the exact
   cap word produced. Also disassemble once whether the gate is `V&1` or `*(V)&1`
   (`TASK_WRITE_SHAPE_20260926.md:125-137` says `*(V)`; both are satisfiable).
2. **bit21 arm hunt.** Loop arms until `(g_waiter_abs - 0x78) & 0x200000`, set
   `g_sbuf[off]=1`, write `A` into `cred+0x38`, then `mount("tmpfs", "/data/local/tmp/glmnt",
   "tmpfs", 0, "mode=0777")` (probe already at `ghostlock_mrx_e.c:2665`). Success = 0.
3. **Closure.** On mount success, copy `/system/bin/sh` to the new tmpfs, `chmod 04755`,
   exec it from a uid-2000 context and check `CapEff` is full / `id` is root. That is the
   full-privileged-root deliverable.
4. **(Only if all-bits caps are required)** switch to route 2: install the kernel-type
   permissive node (startbit 779 fake node) *before* any kernel-domain op, shield, cede
   `real_cred`/`cred = &init_cred`, fork, and verify the child can `open`/`write`
   `/data/local/tmp/rooted.txt` and `execve` `/system/bin/sh`; then optionally set
   `core_pattern = |/path` to spawn a full-cap helper.

---

## 8. Appendix — exact constants used

| item | value (link-time; add `g_slide`) | source |
|---|---|---|
| `cred->cap_permitted` | `cred+0x30` | `TASK_CRED_OFFSETS_20260926.md:60` |
| `cred->cap_effective` | `cred+0x38` | `TASK_CRED_OFFSETS_20260926.md:61` |
| `cred->cap_bset` | `cred+0x40` | `TASK_CRED_OFFSETS_20260926.md:62` |
| `cred->security` | `cred+0x78` | `TASK_CRED_OFFSETS_20260926.md:69` |
| `task->real_cred` / `cred` | `task+0x9E0` / `task+0x9E8` | `TASK_CRED_OFFSETS_20260926.md:79-80` |
| `task->pid` (HKIP shield) | `task+0x820` | `TASK_PID0_RISK_20260926.md:6` |
| `policydb` | `0xffffff800b3b97c0` | `MRX_SYMBOLS_20260926.md:19` |
| `permissive_map.node` / `.highbit` | `policydb+0x1C0` / `+0x1C8` | `TASK_POLICY_PATCH_20260926.md:190-192` |
| `ashmem_misc.fops` | `0xffffff800b1188a8` | `MRX_SYMBOLS_20260926.md:20` |
| `call_usermodehelper_exec_work.cfi` | `0xffffff800819571c` | `FACTS` §5; `MRX_SYMBOLS_20260926.md` |
| `system_unbound_wq` (data) | `0xffffff800add9f30` | `llvm-nm -n` |
| `init_cred` | `0xffffff800adfcd28` | `MRX_SYMBOLS_20260926.md:15` |
| `init_task` | `0xffffff800adeb4c0` | `MRX_SYMBOLS_20260926.md:14` |
| `CAP_SYS_ADMIN` bit | 21 (`0x200000`) | `include/uapi/linux/capability.h` |
| `CAP_SETUID` bit | 7 (`0x80`) | `TASK_CRED_OFFSETS_20260926.md:107-111` |
| window geometry | base `W-0x78`, lock `W-0x30`, waiter `W` | `FACTS 9e`/`9h` |

### One-line answer

Do not try to encode a capability word: **write a kernel pointer whose low 32 bits already
are the mask** — select the stamped window stack address (re-arm until
`(g_waiter_abs-0x78) & CAP_SYS_ADMIN`) and store it into `cred+0x38`
(`ghostlock_mrx_e.c:488-508` retargeted to bit 21). `FACTS 9al(2)` already proves the store
lands; the missing piece was only bit selection. UMH (route 1) and ashmem-RW (route 2) are
not reachable with a pointer/zero primitive; the kernel-permissive cede (route 2/5) is the
path to *all* capability bits.
