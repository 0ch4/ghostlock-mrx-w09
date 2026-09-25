# TASK: `task_struct.pid == 0` (HKIP shield) on MRX-W09 / Kirin 990, Linux 4.14.116

Host-side static analysis only. No adb, no device, no runtime. Sources read:
`[WORKSPACE]\huawei_kernel_src\Code_Opensource\kernel` (the shipped tree);
config cross-checked against
`arch/arm64/configs/merge_kirin990_defconfig`. `task_struct.pid == +0x820` is
taken from the exploit's established offsets (corroborated in
`COPY_PROCESS_FORKSTORM_20260923.md:157`, `ZERO_WRITE_ENDGAME_20260923.md:19`,
`ERASE_SHAPES_AND_ZERO_TARGETS_20260923.md:103`); it was not re-derived here.

---

## 0. Verdict (short)

| Question | Answer |
|---|---|
| Does `task_pid_nr()` equal `task_pid_vnr()`? | **No.** `task_pid_nr()` returns the cached `tsk->pid` (`sched.h:1620-1623`); `task_pid_vnr()`/`task_tgid_vnr()`/`task_*_nr_ns()` walk `tsk->pids[...].pid` (the `struct pid`) (`sched.h:1630-1634`, `pid.c:521-540`). Zeroing `+0x820` corrupts **only** the cached field and `task_pid_nr`. |
| Why does exiting panic? | `do_exit()` has `if (unlikely(!tsk->pid)) panic("Attempted to kill the idle task!");` — **`kernel/exit.c:786-787`**. It is the first pid-related statement in `do_exit` and fires before `exit_signals`/`exit_notify`/`release_task`. |
| Are there *other* pid-0 panics in the exit chain? | **No reachable one.** The rest of the chain uses `struct pid` (`detach_pid`/`free_pid`), which is intact. See §2. |
| Is the pid bitmap indexed at 0? | **No.** The bitmap is indexed by `struct upid.nr` (the real pid), never by `task->pid`. Bit 0 is reserved and never freed. See §2.3. |
| Does restoring `pid` + another `setresuid(0,0,0)` close the root loop? | **No.** The bit is never written while `pid==0` (`hkip_set_task_bit` no-ops), and after the restore `prepare_creds()` runs `hkip_check_xid_root()` **before** `commit_creds()`, sees root creds + clear bit, and `force_sig(SIGKILL)`. See §3. |
| Viable closure | Fork **while still shielded**: the child gets a real pid, and `hkip_init_task()` writes the child's HKIP root bits. (Already the route landed in `CEDE_LANDED_20260924.md`.) See §3.3. |
| Exit / kill while `pid==0` | Any fatal signal (external `kill -9`, or HKIP's own `force_sig(SIGKILL)`) → `do_exit` → **kernel panic**. The task is effectively unkillable. See §2.1. |

---

## 1. (a) Who reads `task->pid` directly

### 1.1 The three different "pid" accessors

```
include/linux/sched.h:1620  static inline pid_t task_pid_nr(struct task_struct *tsk)
include/linux/sched.h:1622      return tsk->pid;              <-- cached field
include/linux/sched.h:1636  static inline pid_t task_tgid_nr(struct task_struct *tsk)
include/linux/sched.h:1638      return tsk->tgid;             <-- cached field (NOT zeroed)
include/linux/sched.h:1630  static inline pid_t task_pid_vnr(struct task_struct *tsk)
include/linux/sched.h:1632      return __task_pid_nr_ns(tsk, PIDTYPE_PID, NULL);
include/linux/sched.h:1682  static inline pid_t task_tgid_vnr(struct task_struct *tsk)
include/linux/sched.h:1684      return __task_pid_nr_ns(tsk, __PIDTYPE_TGID, NULL);
```

`__task_pid_nr_ns()` (`kernel/pid.c:521-540`) reads
`rcu_dereference(task->pids[type].pid)` and calls `pid_nr_ns()` (`pid.c:501-512`),
which returns `pid->numbers[ns->level].nr` — i.e. the **`struct pid`**, not
`task->pid`. `pid_alive()` likewise tests `p->pids[PIDTYPE_PID].pid != NULL`
(`sched.h:1651-1654`).

Consequence: the exploit's zero write at `task+0x820` changes `task_pid_nr()`
(and direct `->pid` reads) but leaves `task_pid_vnr()`, `task_tgid_nr()`,
`task_tgid_vnr()`, `task_*_nr_ns()`, `pid_alive()` and all `struct pid`-based
lookups correct. `tgid (@0x824)` is untouched by the 4-byte zero, so thread-group
and `is_global_init` semantics survive (`sched.h:1749-1752` uses `task_tgid_nr`).

### 1.2 HKIP itself

`drivers/hisi/hhee/hkip/critdata.c` / `include/linux/hisi/hisi_hkip.h`:

```
hisi_hkip.h:63  __hkip_get_task_bit(bits, task)   -> hkip_get_bit(bits, task_pid_nr(task), PID_MAX_DEFAULT)
hisi_hkip.h:69  hkip_get_task_bit(bits, task, def)-> pid = task_pid_nr(task); if (pid != 0) read bit; else return def
hisi_hkip.h:78  hkip_set_task_bit(bits, task, val) -> pid = task_pid_nr(task); if (pid != 0) hkip_set_bit(...)   // NO-OP at pid 0
```

`pid==0` ⇒ every `hkip_get_*` returns `def_value` and every `hkip_set_*` is a
no-op. The callers pass `def_value = true` for the root/addr-limit checks
(`hkip_get_current_bit(hkip_uid_root_bits, true)` etc., `critdata.c:57,93`;
`hkip_is_kernel_fs()` `hisi_hkip.h:117-119`). That is the whole shield.

### 1.3 Core paths that read the cached `task->pid` / `task_pid_nr`

| Subsystem | Site | Notes |
|---|---|---|
| exit | `kernel/exit.c:786` `if (unlikely(!tsk->pid))` | **panic** |
| exit (log) | `kernel/exit.c:842` `task_pid_nr(current)` | "exited with preempt_count" message |
| exit (die-catch) | `kernel/exit.c:1017` | `catch_unexpected_exit` log |
| signals | `kernel/signal.c:1264` `to_pid = p->pid`; `:1268` `current->pid`, `p->pid`; `:1270` `current->pid != 1`; `:1282` `current->pid != 1`, `to_pid != current->pid` | all inside `CONFIG_HW_DIE_CATCH=y`; logging / SIGKILL→SIGABRT rewrite decisions |
| signals (misc) | `kernel/signal.c:257`, `3929` | printk / kdb |
| sched | `kernel/sched/core.c:6152-6155` | `sched_show_task` debug |
| sched (Huawei) | `kernel/sched/core.c:3183` `p->parent->pid <= 2` | `task_should_forkboost`, `CONFIG_HISI_EAS_SCHED`; a pid-0 parent's children lose fork-boost |
| sched debug | `kernel/sched/debug.c:545`, `:745` | sysrq/`/proc/sched_debug` |
| proc | `fs/proc/base.c:992` `sched_hwstatus_updatefg(task->pid, task->tgid)` | `CONFIG_SCHED_HWSTATUS=y`; reads cached `->pid` |
| proc (warn) | `fs/proc/base.c:1224-1225` | oom_adj deprecation warn |
| arm64 mm | `arch/arm64/include/asm/mmu_context.h:43` `write_sysreg(task_pid_nr(next), contextidr_el1)` | `CONFIG_PID_IN_CONTEXTIDR=y`; called at `arch/arm64/kernel/process.c:499` |
| ftrace | `kernel/trace/trace.c:1932`, `:2022` | `!tsk->pid` ⇒ "idle" early-return |
| psi | `kernel/sched/psi.c:754` | `!task->pid` ⇒ early-return |
| kexec | `kernel/kexec_core.c:88` | `!p->pid` ⇒ crash-kernel trigger |
| audit filter | `kernel/auditfilter.c:1319` | `pid = task_pid_nr(current)` for `audit_rule` |
| oom / panic / printk / lockdep / watchdog / workqueue … | many | log formatting only |
| drivers (Huawei + misc) | `drivers/staging/android/ion/ion.c:97,120`; `drivers/gpu/drm/hisi/heap/hisi_drm_heaps_tracer.c:117`; `drivers/hisi/hisi_cma/hisi_cma_debug.c:526`; `fs/f2fs/trace.c:56`; `include/linux/coresight.h:352` | `task_pid_nr` used as user id |

### 1.4 Paths that are **struct-pid based** and therefore unaffected

* `getpid`/`getppid` — `task_tgid_vnr` (`sched.h:1682`).
* `kill`/`tgkill` — `find_vpid()` → `find_pid_ns()` (`pid.c:381-384`, `:367`).
* `/proc/<pid>` lookup/readdir — `find_task_by_vpid`, `next_tgid` → `find_ge_pid`
  (`pid.c:554`).
* `/proc/<pid>/stat`, `status` — `task_tgid_nr_ns` / `task_pid_nr_ns`
  (`fs/proc/array.c:171,177,220,223,503`); the `struct pid` is intact, so the
  displayed numbers are still the **real** ones.
* ptrace attach — `find_task_by_vpid` (`kernel/ptrace.c:1124`).
* futex — `find_task_by_vpid` (`kernel/futex.c:892,3444`) and `task_pid_vnr`
  (`:1161,1380,1532,1922,2454,3000,3482`).
* fork — child pid assigned from the freshly allocated `struct pid`:
  `p->pid = pid_nr(pid)` (`kernel/fork.c:1959`), `p->tgid` (`:1970`).
* signals `si_pid` — `task_tgid_nr_ns`/`task_pid_nr_ns` (`signal.c:1126,1766,1852`).
* exit bookkeeping — `detach_pid`/`free_pid` use `struct pid` (see §2.2).
* audit — `task_tgid_nr` (`kernel/auditsc.c:2016,2417,…`).
* SELinux/`cap_capable` decisions — credentials, not pid.

---

## 2. (b) The exact panic path(s)

### 2.1 `do_exit()` — the one and only panic

```
kernel/exit.c:774  void __noreturn do_exit(long code)
kernel/exit.c:776      struct task_struct *tsk = current;
...
kernel/exit.c:784      if (unlikely(in_interrupt()))
kernel/exit.c:785              panic("Aiee, killing interrupt handler!");
kernel/exit.c:786      if (unlikely(!tsk->pid))
kernel/exit.c:787              panic("Attempted to kill the idle task!");
```

* This is reached from `sys_exit` (`exit.c:963-966`), `do_group_exit`
  (`exit.c:996`), and every fatal-signal path.
* The nearby panic at `exit.c:857-859` (`"Attempted to kill init!"`) is keyed on
  `is_global_init(tsk)` = `task_tgid_nr(tsk) == 1` (`sched.h:1749-1752`); since
  `tgid` is **not** zeroed, it is not triggered.
* The `PF_EXITING` recursive-fault branch at `exit.c:809-823` is only
  `pr_alert` + `schedule()`, not a panic.
* Because line 786 is the first pid check, the entire rest of the exit chain is
  **unreachable** for a `pid==0` task. That makes `hkip_check_*`'s
  `force_sig(SIGKILL, current)` (`critdata.c:68,102`) a guaranteed panic when the
  task is shielded: SIGKILL → `get_signal` → `do_group_exit` → `do_exit` → line 786.

### 2.2 The downstream chain is otherwise safe (struct-pid based)

For completeness, if the guard at `exit.c:786` did not exist, the trace
`do_exit → exit_notify → release_task → __exit_signal → __unhash_process →
detach_pid → free_pid/put_pid` does **not** index anything by `task->pid`:

```
kernel/exit.c:709   exit_notify()
kernel/exit.c:716       forget_original_parent()      // BUG_ON at :688 is a ptrace invariant, unrelated
kernel/exit.c:727,730   do_notify_parent()            // signal.c:1766 uses task_pid_nr_ns -> struct pid
kernel/exit.c:188   release_task()
kernel/exit.c:204       __exit_signal()
kernel/exit.c:159           __unhash_process()
kernel/exit.c:78                detach_pid(p, PIDTYPE_PID)
kernel/pid.c:416    detach_pid() -> __change_pid()
kernel/pid.c:404        pid = link->pid;              // struct pid pointer, intact
kernel/pid.c:413        free_pid(pid)
kernel/pid.c:258    free_pid():  for (i = 0; i <= pid->level; i++) upid = pid->numbers + i;
kernel/pid.c:290                    free_pidmap(pid->numbers + i);
kernel/pid.c:104    free_pidmap():  nr = upid->nr;   // the REAL pid, not task->pid
```

`exit_signals()` (`signal.c:2569`) and its `BUG_ON`s (`signal.c:279,331`) are
jobctl-based and unrelated. So a `pid==0` task whose guard were removed would
mostly exit cleanly except for the debug/trace side effects of §4.

### 2.3 Can `task->pid == 0` index the pid bitmap at 0?

**No, under this exploit.** The exploit zeroes only the cached `task->pid`
(`Ts+0x820`); it does **not** touch `thread_pid`/`struct pid` or
`pid->numbers[].nr`. Every pid-bitmap operation goes through `struct upid.nr`:

* `free_pidmap()` computes `map = upid->ns->pidmap + nr / BITS_PER_PAGE` and
  `clear_bit(nr & BITS_PER_PAGE_MASK, map->page)` (`pid.c:104-112`).
* Bit 0 is reserved at boot: `set_bit(0, init_pid_ns.pidmap[0].page)` with the
  comment *"Reserve PID 0. We never call free_pidmap(0)"* (`pid.c:593-595`).
* Even if `nr` ever became 0, `alloc_pidmap()` never hands out a pid below
  `RESERVED_PIDS` (300): it starts at `last+1`, clamps to `RESERVED_PIDS`
  (`pid.c:159-160`) and on wrap sets `offset = RESERVED_PIDS` (`pid.c:205-206`).

So `free_pidmap(0)` / a zero-index clear is **not** reachable from zeroing
`task->pid` alone. (If someone also zeroed `struct pid.numbers[].nr`, `free_pidmap(0)`
would clear the reserved bit and `atomic_inc(&map->nr_free)`, but allocation still
would not produce 0. That extra corruption is not part of this exploit.)

**Only panic path: `kernel/exit.c:786-787`.**

---

## 3. (c) Is restoring `task->pid` after becoming root a viable escape?

### 3.1 What actually happens while `pid==0`

* `setresuid(0,0,0)` → `SYSCALL_DEFINE3(setresuid)`:
  * `new = prepare_creds()` (`kernel/sys.c:640`).
    `prepare_creds()` ends with:
    ```
    kernel/cred.c:282   if (unlikely(hkip_check_xid_root()))
    kernel/cred.c:283       goto error;
    ```
    With `pid==0`, `hkip_get_current_bit(hkip_uid_root_bits, true)` returns
    `def_value = true` (`hisi_hkip.h:69-76`), so `hkip_check_uid_root()` returns 0
    immediately (`critdata.c:57-59`). It **passes**.
  * `commit_creds(new)` (`kernel/sys.c:681`) → `kernel/cred.c:498`
    `hkip_update_xid_root(new)` → `hkip_set_current_bit()` (uid + gid) →
    `hkip_set_task_bit(bits, current, value)`. But:
    ```
    hisi_hkip.h:81   pid_t pid = task_pid_nr(task);   // == 0
    hisi_hkip.h:82   if (pid != 0)
    hisi_hkip.h:83       hkip_set_bit(...);           // skipped
    ```
  * **No HKIP bit is written.** The claim in
    `CONSUMER_ONLY_ENDGAME_20260924.md:17` ("commit_creds() -> hkip_update_xid_root()
    gives THIS thread its OWN HKIP bit") is **false for the pid-0 case**.
* At task creation, `hkip_init_task()` (`fork.c:1985`, `critdata.c:129-144`) had
  written the bit for the real pid based on the *fork-time* creds (normally
  non-root ⇒ **bit = 0**). So after the cede, the real pid's bit is clear.

### 3.2 Restoring `pid` and re-running `setresuid`

After `current->pid` is restored to its real (nonzero) value:

* The next `setresuid`/`setgid`/`capset`/`execve`/key syscall calls
  `prepare_creds()` first, which calls `hkip_check_xid_root()` (`cred.c:282`).
  Now `pid != 0`, the bit is 0, and `current_cred()` is **already root**
  (`hkip_compute_uid_root` is true, `critdata.c:42-51`). Therefore:
  ```
  critdata.c:65   if (unlikely(hkip_compute_uid_root(creds) || uid_eq(creds->fsuid, GLOBAL_ROOT_UID))) {
  critdata.c:67       pr_alert("UID root escalation!\n");
  critdata.c:68       force_sig(SIGKILL, current);
  critdata.c:69       return -EPERM;
  ```
  `prepare_creds()` fails (`cred.c:283`), so `commit_creds()` — the only thing
  that would write the bit — is **never reached**. The pending SIGKILL then runs
  `do_exit`, which is now panic-free (pid nonzero), so the process simply dies.
* This is independent of `setresuid`: after the restore, the next
  `__cap_capable()` (`security/commoncap.c:85`) or a DAC check on a root-owned
  inode (`fs/namei.c:301-307`) triggers the same `hkip_check_*` and kills the task.

**Verdict: the loop does NOT close.** `task->pid` can be restored, but you cannot
reach `commit_creds` afterwards to write the bit, because `prepare_creds`'s
`hkip_check_xid_root` kills you first. Restoring the pid therefore *converts a
panic into a clean process death*; it does not yield a surviving root task.

This matches the on-device result recorded in `CEDE_LANDED_20260924.md:36-38`:
*"a root-looking task is SIGKILLed synchronously by HKIP (exit 137, no panic). The
cached `task->pid == 0` shield ... is what prevents it. The pid-RESTORE removes
the shield, so the next store triggers the synchronous process kill."* The
"optional, now safe because the bit is set" step 7 in
`CONSUMER_ONLY_ENDGAME_20260924.md:23` is unsound for the same-pid restore.

### 3.3 What *does* close the loop

1. **Fork while still shielded (proven route).** `copy_process()`:
   * `hkip_check_xid_root()` on the parent (`fork.c:1716`) passes because the
     parent is still `pid==0`.
   * the child gets a **real** pid: `p->pid = pid_nr(pid)` (`fork.c:1959`),
     `p->tgid = p->pid` (`fork.c:1970`).
   * `hkip_init_task(p)` (`fork.c:1985`) then writes the child's bits for its
     **nonzero** pid, using the child's inherited (root) creds:
     `hkip_set_task_bit(hkip_uid_root_bits, task, hkip_compute_uid_root(creds))`
     (`critdata.c:136-139`). The child is born with a valid pid **and** its HKIP
     root bits already set.
   * The child can be a working root process and can exit normally.
   * **Caveat:** the `pid==0` parent must never exit (or be killed) — see §4.
2. **Race the `prepare_creds`→`commit_creds` window.** In one thread run the
   credential syscall; concurrently, with the arbitrary-write primitive, flip
   `current->pid` from 0 to the real pid between `prepare_creds()` and
   `commit_creds()`. `commit_creds` would then write the bit for the real pid.
   Narrow window, needs concurrent write to the same `task_struct`; **uncertain**.
3. **Write the protected bit page out of band.** The HKIP bit pages are
   registered with EL3 via `hkip_hvc3(HKIP_HVC_ROWM_REGISTER, ...)`
   (`critdata.c:23-32`) and are only mutated through `hkip_hvc4`
   (`hisi_hkip.h:53-61`). A plain kernel store to `hkip_uid_root_bits` is expected
   to be trapped/denied by the EL3 read-only-write monitor. Whether the GhostLock
   write primitive can defeat ROWM is **not established here** (no device work).
4. **Restore to a pid whose bit is already 1** (e.g. pid 1, a root task). This
   satisfies `hkip_get_task_bit` and avoids the kill, but it desynchronises
   `task->pid` from `struct pid` (`task_pid_nr != task_pid_vnr`), confusing the
   §1.3 sites (ftrace/psi/CONTEXTIDR/sched debug). Hacky and **uncertain**.
5. **Restore to an arbitrary large pid** is unsafe: `hkip_set_bit()` calls
   `hkip_hvc4` without a range guard of its own and `BUG()`s if the HVC returns
   nonzero (`hisi_hkip.h:53-61`); choose a value `< PID_MAX_DEFAULT`.

---

## 4. (d) Side effects of `task->pid == 0` for a user task that must keep working

### 4.1 Scheduling
* Scheduler core does not read `task->pid`; context switch is task-pointer based,
  so the task **is** scheduled normally.
* `CONFIG_PID_IN_CONTEXTIDR=y` (`merge_kirin990_defconfig:6214`) ⇒
  `contextidr_thread_switch()` writes `task_pid_nr(next) == 0` into
  `CONTEXTIDR_EL1` on every switch (`mmu_context.h:38-45`, called from
  `arch/arm64/kernel/process.c:499`). It thereby collides with the idle task's
  context id; hardware breakpoints/watchpoints/Coresight that match on
  `CONTEXTIDR` may misbehave for this task.
* `CONFIG_HISI_HHEE_ADDR_LIMIT_PROTECTION` path: `uao_thread_switch()`
  (`process.c:439`) and `hkip_is_kernel_fs()` (`hisi_hkip.h:117-119`) call
  `hkip_get_task_bit(..., true)`, so a pid-0 task is treated as `KERNEL_DS`
  (UAO forced). That is part of the shield and means the addr-limit gate is off.
* `task_should_forkboost()` (`sched/core.c:3183`) treats children of a pid-0 task
  as children of init/kthreadd (`p->parent->pid <= 2`), so they do not get
  fork-boost.

### 4.2 Syscalls, creds, capabilities
* All `struct pid`-based syscalls work: getpid/getppid, kill/tgkill, ptrace,
  futex, `/proc`, `fork`, signals.
* `__cap_capable()` starts with `hkip_check_uid_root()` (`commoncap.c:85`), and
  `acl_permission_check()` calls `hkip_check_uid_root/gid_root` for root-owned
  inodes (`namei.c:301-307`). For **non-root** creds these return 0, so the task
  works. For a root-credible task they only kill once `pid != 0`; while shielded
  (`pid==0`) the `def_value=true` path keeps them returning 0.
* `syS_setresuid` additionally runs Huawei's `checkroot_setresuid(old->uid.val)`
  (`kernel/sys.c:677-679`, `security/check_root/check_root.c:90-93`). With
  `CONFIG_HUAWEI_PROC_CHECK_ROOT=y` (`defconfig:6284`) this can SIGKILL/deny a
  non-shell third-party uid **only if `CONFIG_CHECKROOT_FORCE_STOP` is set**;
  otherwise it just logs and increments counters (`check_root.c:52-77`). Not
  pid-related, but another gate on the `setresuid` plan.

### 4.3 Files, SELinux, audit
* DAC/SELinux decisions use `cred`/`cred->security`, not pid, so file access
  works if the creds/SID permit.
* Audit uses `task_tgid_nr` (`auditsc.c:2016,2417,…`) → correct real tgid.
* One SELinux warning prints `task_pid_nr(current)` (`security/selinux/hooks.c:5159`)
  → prints **0**; cosmetic. `fs/proc/base.c:992` feeds `task->pid` (0) into
  `sched_hwstatus_updatefg`; also cosmetic/accounting.

### 4.4 Kernel-thread / idle misclassification
The tests that treat `!task->pid` as "idle/kernel":
* `trace_save_cmdline()` returns success without saving `comm`
  (`kernel/trace/trace.c:1932-1933`); `trace_save_tgid()` returns without
  recording tgid (`trace.c:2022-2023`). ftrace output for this task loses
  cmdline/tgid.
* `psi_task_change()` returns early (`kernel/sched/psi.c:754-755`), so PSI
  pressure accounting skips this task.
* `kexec_core.c:88` treats it as a crash trigger.
(The authoritative kernel-thread flag is `PF_KTHREAD`; these `!pid` tests are
idle-task specific. `is_global_init` uses `tgid`, so it is not fooled — good,
otherwise every `pid==0`/`tgid==1` coincidence would make `do_exit` panic at
`exit.c:857`.)

### 4.5 RCU / lifetime
* RCU does not classify a task as a kernel thread by pid; `exit_rcu()`,
  `exit_tasks_rcu_start/finish()` are task-pointer based. No RCU break from
  `pid==0` alone.
* The task is still fully a user task (`PF_KTHREAD` clear, `mm` present, `tgid`
  valid), so it is reaped/parented normally — provided it never calls `do_exit`.

### 4.6 Exit / kill
* Cannot exit and cannot be killed: any fatal signal reaches `do_exit` and panics
  at `exit.c:786`. OOM-kill, `kill -9`, `SIGSEGV`, or an HKIP `force_sig(SIGKILL)`
  all panic the kernel while the task is shielded. This is the overriding
  operational risk: a shielded task is a kernel panic waiting for a signal.

---

## 5. Explicit uncertainty

* The `task+0x820 = pid` offset is assumed from the exploit's prior derivation
  and repo docs; not independently re-derived this session.
* The assertion that a plain kernel write to the HKIP bit pages is denied by
  EL3/ROWM is inferred from the HVC-only set path (`critdata.c:23-32`,
  `hisi_hkip.h:53-61`); untested here.
* "restore pid, then race commit_creds" and "restore to a bit-set pid" are
  theoretical; no runtime validation was performed (host-only task).
* `checkroot_setresuid` behavior depends on build-time flags
  (`CONFIG_CHECKROOT_FORCE_STOP`) not confirmed in the defconfig excerpt read.
* The exact interaction of a pid-0 task with HW breakpoints via `CONTEXTIDR=0`
  is a reasoned side effect, not measured.
