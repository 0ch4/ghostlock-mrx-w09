# GhostLock (CVE-2026-43499) — ENDGAME TECHNIQUES to uid-0 under SELinux-Enforcing + a hypervisor integrity check

Date: 2026-09-23 (sub-agent survey, saved by the parent session)

Target of record: Huawei MRX-W09, Kirin 990, Linux 4.14.116 (EMUI), SELinux enforcing,
HKIP/HHEE active, LTO+CFI, DEBUG_SPINLOCK.
Scope: survey of the local 89-repo PoC collection `ghostlock_pocs\` for techniques that go
from an arbitrary-write primitive to uid 0 while satisfying SELinux-Enforcing and a
hypervisor/integrity gate (our HKIP). Looks deeper than `EXTERNAL_POC_SURVEY_20260923.md`
(which only covered the write layer).

Our primitive (`MRX_W09_GHOSTLOCK_FACTS.md` §9h/§9k): an 8-byte store `*(target) = value`
whose `value` must be a readable kernel address with an ODD first word (RB_BLACK invariant
of the re-insert), plus a side-store at `value&~3 + 8/0x10`.

---

## 0. Executive summary (6 techniques that matter for us)

| # | Technique | Source repo | Needs | Beats which dead end |
|---|-----------|-------------|-------|----------------------|
| T1 | Point `cred->security` at an EXISTING valid `task_security_struct` whose first word is odd (e.g. `init_cred.security`, first dword `osid=1`) | OPPO/pixel `patch_cred_sid`; Huawei MDS-AL00 | 1 pointer write + read of `init_cred+0x78` | sid=1 without a small-int write; no fake-blob kfree (object is real) |
| T2 | Write `{osid,sid}={1,1}` INTO the existing blob (never change the pointer) | `GhostLock-OPPO-PCKM00`, `vivo-root-build`, `CVE-2026-43499-root-KernelSU`, `pixel-ksu-root` | a raw small-integer write (Case-2 shape) | sid=1, zero kfree risk |
| T3 | `selinux_state` enforcing byte := 0 via 8-byte store with low byte 0 (value = aligned direct-map page VA) | `GhostLock-H80GT`, `ghostlock-a17`, `ghostlock-pfem10`, `GhostLock-OPPO-PCKM00` (4.14) | 1 pointer write | neutralizes SELinux without touching `cred->security` |
| T4 | `task->cred = &init_cred` on a forked/anchor task (kernel SID) | `GhostLock-H80GT`, `cve-2026-43499-aak-an00`, `CVE-2026-43499-root-KernelSU`, `vivo-root-build` | 1-2 pointer writes (+ pre-forked helper) | SELinux half only; must pair with a legal `commit_creds` |
| T5 | UMH via forged `work_struct` -> `call_usermodehelper_exec_work` | `ghostlock-a17/src/core/umh_root.c`, ZFOLD4, A36, s26-m1q | full kernel RW | HKIP-legal by construction (kworker already has the bit) |
| T6 | Fake COMPLETE cred on a held spray page (uid 0, caps full, `user`/`user_ns`/`group_info`/`security` valid, `usage` huge) | `ghostlock-pfem10`, `vivo-root-build` | full RW + held page | solves "fake cred must be complete" and kfree/UAF |

Best HKIP fit: T3 (or T1/T2) + `cred->cap_effective` (verified) + `setresuid(0,0,1)` ->
`commit_creds -> hkip_update_xid_root` (only commit_creds sets the bit). T5 is the best
HKIP-independent fallback if full RW is ever obtained.

---

## 1. SELinux neutralization via sid / kernel domain

### 1.1 Canonical `{osid,sid}={1,1}` write INTO the existing blob
Files: `GhostLock-OPPO-PCKM00/exploit/src/root.c`, `CVE-2026-43499-root-KernelSU/src/root.c`,
`pixel-ksu-root/cves/lib/root/cred.c`, `vivo-root-build/src/root.c`,
`GhostLock-OPPO-PCKM00/exploit/targets/oppo-pckm00/target.h`. Kernel: OPPO 4.14.180.
```c
int patch_cred_sid(int fd, uintptr_t cred) {
  uint64_t security = pipe_read64(fd, cred + CRED_SECURITY_OFF);
  if (!is_direct_ptr(security)) { ... return 0; }
  uint32_t sid_pair[2] = { target_cred_osid, target_cred_sid };   // {1,1}
  uintptr_t osid_addr = security + selinux_cred_blob_off + SELINUX_CRED_OSID_OFF;
  return pipe_phys_write_data(fd, osid_addr, sid_pair, sizeof(sid_pair));
}
```
4.14 macros (`target.h`): `SELINUX_CRED_BLOB_OFF 0`, `SELINUX_CRED_OSID_OFF 0`,
`SELINUX_CRED_SID_OFF 4`, `SELINUX_KERNEL_SID 1`.
`struct task_security_struct` = `{u32 osid; u32 sid; u32 exec_sid; u32 create_sid;
u32 keycreate_sid; u32 sockcreate_sid;}`. Setting osid=sid=1 makes SELinux evaluate as
`u:r:kernel:s0`. Pointer untouched -> `selinux_cred_free` frees the ORIGINAL object -> no crash.
Caveat: sid=1 is MAC root, not DAC root (cap_capable still blocks uid 2000); pair with
`cap_effective` + `setresuid`. Requires a raw-value write shape.

### 1.2 MRX-W09 `--sid` design and the refcount-safe corrections
(a) point at an existing real tsec instead of a fake one: `init_cred.security` is a real
kmalloc'd tsec with osid=sid=1 and first 8 bytes `0x0000000100000001` (ODD). One write:
`*(our_task->cred + 0x78) = *(init_cred + 0x78)`. Keep our cred's `usage > 0` (resident
child, aak-an00 pre-writer rule) so it is never freed.
(b) fake-but-complete cred, huge `usage`, blob on a held page (T6).

### 1.3 Honor/Huawei `selinux_state` refactor
`cve-2026-43499-honor/docs/report.md`: `SELINUX_ENFORCING 0x0225a420` reconstructed as
`selinux_state.enforcing` (field offset 0x00, bool); `selinux_state` symbol
`0xffffffc00a827fa8`; `get_selinux_enforcing()` does `kallsyms_lookup_name("selinux_state")`
then `ldrb w0,[x0] # +0`. Derive `selinux_state` from nm, read the field offset from the
authoritative reader (`avc_denied` / `sel_write_enforce`).

### 1.4 Fake complete cred including a `security` blob (refcount-safe)
`ghostlock-pfem10/src/core/payload.c:454-490` (OPPO 5.10.236):
```c
put32(c, CRED_USAGE, 0x40000000);          // never freed
put32(c, CRED_UID, 0);                      // + gid/... all 0
put64(c, CRED_CAP_*, 0x1FFFFFFFFFFULL);     // inh/prm/eff/bset/amb
put64(c, CRED_USER,       p0_data_alias(ROOT_USER));
put64(c, CRED_USER_NS,    p0_data_alias(INIT_USER_NS));
put64(c, CRED_GROUP_INFO, p0_data_alias(INIT_GROUPS));
put64(c, CRED_SECURITY,   payload_base + SECBLOB_OFF);
// secblob: put32(s,0x00,1) osid=KERNEL; put32(s,0x04,1) sid=KERNEL
```
Must be complete: `alloc_pipe_info`/`get_current_user`, `in_group_p`, `ns_capable` deref
`user`/`user_ns`/`group_info`; NULL `user_ns` panics. `commit_creds` hard-BUGs unless
`task->cred == task->real_cred`; `setresuid`/`setresgid` are exempt and used to "launder"
the fake cred into a real one. `vivo-root-build/src/root.c:494-551` does the same and swings
BOTH `real_cred` and `cred`.

---

## 2. Directly disabling SELinux

### 2.1 8-byte write with low-byte zero (pointer-write compatible)
`GhostLock-H80GT/exploit/src/sysctl.c:897-958`, `ghostlock-pfem10/src/core/exploit.c:802-857`,
`ghostlock-a17/src/core/umh_root.c:151-158`.
```c
#define SELINUX_ENFORCING_OFF 0x2e84b38ULL  // selinux_state+0
setenv("W_VALUE_DM","1",1); sysctl_w_value=0; /* prepare_dm_page -> dm base+0x100 */
sysctl_w_target = text_addr(KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF);
sysctl_do_walk(pred_enforce, NULL, "selinux");
```
The write value is an aligned direct-map page address (low byte 0) -> `enforcing = 0`.
`selinux_state+0` is authoritative per `avc_denied` disasm (`ldarb [x0]`).
**4.14 variant:** `GhostLock-OPPO-PCKM00/exploit/targets/oppo-pckm00/target.h:194-199`:
```c
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + 0x025b19d8ULL + 0x04ULL)
```
i.e. on that 4.14 build the authoritative enforcing byte is `selinux_state+0x04`, not +0.
=> Our "compile-time constant" conclusion must be re-checked by disassembling
`avc_denied`/`sel_write_enforce`. NOTE: our primitive stores a kernel ADDRESS; its byte4 is
always 0xff, so we can only zero a field at an offset whose byte we control (offset 0 if
the address is aligned). If enforcing is truly at +4 this route is NOT usable with a
pointer write.

### 2.2 `loggers[] & ~0xff` variant
`cve-2026-43499-aak-an00/docs/02-...md:108`: on that Honor build `selinux_state.enforcing`
is inert; nudge the adjacent `loggers[]` KASLR-anchor global with "default & ~0xff".

### 2.3 `selinux_state` layouts seen
- Honor 6.1: `enforcing @ +0x00`.
- Honor 5.10.2xx: `{enforcing@0, decoy@1, initialized@2, policycap@3..}`.
- OPPO 4.14: authoritative enforcing at `selinux_state+0x04`.
- 5.4.210: `+0 disabled, +1 enforcing, +2 checkreqprot, +3 initialized, +4..+9 policycap[6],
  +10/+11 pad, +12 avc ptr, +16 ss ptr`.

---

## 3. AVC cache / LSM-hook neutralization

### 3.1 AVC poisoning
`CVE-2026-43499-Neo11Plus/exploit/src/posture.c:262-319`. Force cached decisions
`avd.allowed=0xffffffff`. Limitations: only ALREADY-CACHED entries; needs heap RW + the
`selinux_avc` hlist walk. Our fresh `capset`/`setresuid` deny is not cached -> useless for us.

### 3.2/3.3 LSM hook patching / `security_hook_heads.capable`
`security_hook_heads` (incl. `capable`) is `RO_DATA/__ro_after_init`, read-only in both
mappings -> cannot be zeroed. Confirmed by multiple ports. DO NOT RETRY.

---

## 4. Capability / `setresuid` paths

- `cap_effective` hole confirmed (`cred->caps`: securebits@36, cap_inheritable@0x28,
  cap_permitted@0x30, cap_effective@0x38, cap_bset@0x40, cap_ambient@0x48,
  CRED_SECURITY_OFF 0x78). `CAP_FULL = 0x1FFFFFFFFFF` (5 words, not -1). HKIP never reads
  cap_effective.
- `commit_creds` BUG_ON compares POINTERS (`task->cred` vs `task->real_cred`);
  setresuid/setresgid exempt. Any cred swap must write BOTH `real_cred` and `cred` to the
  SAME value.
- Pre-writer child (`cve-2026-43499-aak-an00/docs/02`): fork a child W before the first
  write; parent writes real_cred, W writes cred; W must `pause()` forever. Order: real_cred
  (task+0x818) FIRST, then cred (+0x820).
- Launder: one `setresuid(0,0,0)` runs `prepare_creds()` (fresh memcpy + 
  `security_prepare_creds`) then `commit_creds()` -> repairs the split AND calls
  `hkip_update_xid_root` -> HKIP bit.

---

## 5. `init_cred` swap, fork-storm, HKIP bit

### 5.1 `task->cred = &init_cred` (kernel SID) — value alignment
`GhostLock-H80GT/exploit/src/sysctl.c:811-857`:
```c
uintptr_t cred_val = text_addr(INIT_CRED);   // aligned init_cred (bit0=0) REQUIRED
sysctl_w_value = cred_val; sysctl_w_target = st.task_ptr + cred_off;
```
Never write real_cred (capget would flip while cred=old -> capset -> commit_creds BUG_ON).
The anchored child becomes uid 0 with kernel SID and can write `/sys/fs/selinux/enforce`.
IMPORTANT: H80GT's write shape is "Case-2" ("one non-NULL child, forced NULL, never
rebalances, colour irrelevant") which writes a raw pointer with NO colour/odd constraint.
Our Case-B requires `*(value)` odd, which is why `&init_cred` (usage=4) failed. =>
Prototype a Case-2 shape with a raw-value canary; if it lands, `&init_cred` (and raw
`{osid,sid}` writes) become available.

### 5.2 Fork-storm with `copy_creds` + `hkip_init_task`
`copy_process()` -> `copy_creds()` (`get_cred(parent_cred)`) -> `hkip_init_task()` ->
`hkip_hvc2(0xC6001050, array, pid, value)`. Child is born uid 0, kernel SID, HKIP bit.
Needs the `&init_cred` write (Case-2). Avoid MAIN-fired walks; use a dedicated CPU-7 trigger.

### 5.3 Huawei MDS-AL00 verified chain (arm32)
`ghostlock-cve-2026-43499/exploit/NOTES_L1_arm32_rbwrite.md`,
`NOTES_cred_replacement_arm32.md`, `kernel/OPPO_SYMBOLS.md` (SW5100 5.4.210):
swap current cred <-> init_cred; `uid@+4 / gid@+8 = 0`, `cap_effective@+0x38 = all F`,
`cred security@+0x64 sid=kernel(1)`, clear TIF_SECCOMP/NO_NEW_PRIVS, `selinux_enforcing = 0`;
root child `setuid(0)`. Huawei's kernel is not special at cred/SELinux level; HKIP is ours.

### 5.4 HKIP in the collection
No HKIP/HHEE handling anywhere in the 89 repos. Closest analogues: Samsung KDP/RKP/DEFEX
and Protected-KVM. Lessons: read back after writing (vendor cred may be hypervisor-protected
and reverted); KDP makes cred patching dead -> data-only (enforcing=0 + UMH) or insmod.
Mapping: HKIP is a per-task bit only `commit_creds`/`copy_process` grants -> any
look-root-without-commit is only a means to pass pre-checks so a final `setresuid` reaches
commit_creds. UMH (T5) is the alternative (kworker already has the bit).

---

## 6. UMH via forged `work_struct` (HKIP-clean)

`ghostlock-a17/src/core/umh_root.c:137-329`; also ZFOLD4/A36/s26-m1q root.c.
1. `selinux_state.enforcing := 0`.
2. Walk `system_unbound_wq -> wq -> dfl_pwq(+0xb0) -> pool(+0x00)`.
3. Wait for empty worklist and `nr_idle > 0`.
4. Build fake `struct subprocess_info` on our page: `work.data = pwq | (color<<4) | 5`,
   `work.entry.next/prev = &pool.worklist`, `work.func = call_usermodehelper_exec_work`,
   `complete`, `path`, `argv`, `envp`.
5. Bump `pwq.nr_in_flight[color]`, `nr_active`, `refcnt`; splice `fake.entry` into `pool.worklist`.
6. Wake workers via PTY alloc/dealloc (`posix_openpt`), poll `completion.done`.
7. Worker runs `call_usermodehelper_exec_work()` -> `kernel_execve` our binary as uid 0.
HKIP-legal by construction. Blocks on bootstrapping full RW; our boot_id read + re-armable
multi-walk could supply the reads/writes -> worth a feasibility study.

---

## 7. Bootstrapping full RW from one write (fops hijack)

### 7.1 OPPO/Pixel 4.14: `ashmem_misc.fops -> fake fops -> configfs bin read/write`
`GhostLock-OPPO-PCKM00/exploit/src/{fops.c,util.c,root.c}` (4.14.180): one write sets
`ashmem_miscs[0].fops` to a fake `file_operations` in a sprayed page; 4.14 legacy
`.read/.write` = `configfs_read_bin_file`/`configfs_write_bin_file` -> arbitrary kernel
RW via pread/pwrite on an ashmem fd; then pipe_buffer page rewrite -> physical RW -> cred patch.
CAVEAT: `GhostLock-H80GT/exploit/src/sysctl.c:3-6` says Huawei SELinux denies `/dev/ashmem`
to shell (`open -> EACCES`) -> use the boot_id ctl_table.data hijack (our existing read
primitive) instead. On MRX-W09 the ashmem bootstrap is likely dead.

### 7.2 4.14 configfs offsets
`.../oppo-pckm00/target.h`: `CONFIGFS_READ_BIN_FILE_OFF 0x2bd760`,
`CONFIGFS_WRITE_BIN_FILE_OFF 0x2bd8e8`, `ASHMEM_MISC_FOPS_OFF 0x17f9fd0`. Also
`ghostlock-aresin/target.h` (4.14.186 MTK), `ghostlock-cve-2026-43499-4.19-k40/.../target.h`.

---

## 8. Huawei/Kirin-specific material

| Repo | Device / kernel | Relevance |
|---|---|---|
| `GhostLock-GOT-W29` | MatePad Pro 11, 4.19.157 | Carrier/write-layer only |
| `ghostlock-cve-2026-43499/references/ref_tc3650`, `exploit/ghostlock_arm32.c` | Huawei Watch 4 Pro MDS-AL00, SW5100, 5.4.210 | Huawei chain that ACHIEVED ROOT: uid/gid 0 + caps + sid=1 + enforcing=0 |
| `CVE-2026-43499_HW-CLT-AL01` | Huawei P20 Pro (CLT-L29), 4.14 | Full 4.14 target table: `KIMAGE_TEXT_BASE 0xFFFFFFC000080000`, `SELINUX_ENFORCING +0x0241605C`, task/cred/fops/pipe offsets |
| `cve-2026-43499-honor` | Honor BVL-AN16, 6.1.128 | `selinux_state.enforcing@+0` refactor + disasm method |
| `ghostlock-honor-aak`, `cve-2026-43499-aak-an00` | Honor AAK-AN00 | pre-writer child, `GW_SELINUX`, `u:r:kernel:s0` landing |
| `GhostLock-H80GT` | Honor AGT-AN00, 5.10.236 | Most complete sysctl-route endgame (boot_id hijack + direct-map page + init_cred anchor + enforcing write) |
| `s26-m1q-ghostlock-selinux` | Samsung 6.x | write-shape vs target alias pitfalls; UMH chain |

---

## 9. Mapping against MRX-W09 dead ends

| Dead end | Surviving alternative | Where |
|---|---|---|
| fake `cred->security` -> `selinux_cred_free` kfree crash | (a) write sid INTO the existing blob; (b) point at a REAL tsec (`init_cred.security`, first word odd); (c) fake-complete cred `usage=0x40000000` on a held page | §1.1, §1.4, OPPO root.c:221, pfem10 payload.c:445-490, vivo root.c:494-551 |
| boot_id/sysctl read destructive | H80GT uses it in a FORKED reader (a fault kills only the reader); read primitive reused for OWNER/VERIFY/CRED | `GhostLock-H80GT/exploit/src/sysctl.c:76-142` |
| fork-storm `&init_cred` impossible (even first word) | shape-specific: Case-2 writes a raw pointer, colour irrelevant; H80GT does exactly this | `GhostLock-H80GT/.../sysctl.c:826-836` |
| `selinux_state.enforcing` "unusable" | offset is build-specific: OPPO 4.14 = `+0x04`, Honor 5.10 = `+0`; value = aligned DM page VA gives low byte 0 | §2.1 |
| cap_effective real but SELinux stops setresuid | combine with sid=1 or enforcing=0, then `setresuid(0,0,1)`; or UMH | §4, §2, §6 |
| `security_hook_heads.capable` RO | confirmed impossible; do not retry | Neo11Plus posture-enhancements.md:105-116 |
| HKIP: `task->cred=&init_cred` synchronously fatal | do not make init_cred the FINAL state; use it only to pass SELinux, then `setresuid`; or UMH | §5.4 |
| `--fakecred` incomplete cred | fake cred must be complete + usage huge + held page; then launder with setresuid | pfem10 payload.c:445-490, exploit.c:2459-2598 |

---

## 10. Ranked shortlist for MRX-W09

1. **`selinux_state` enforcing byte := 0 via aligned-DM-page pointer write + `cap_effective`
   + `setresuid(0,0,1)`.** Only one compatible with our pointer-write shape AND leaves
   `cred->security` untouched. Steps: disassemble `avc_denied`/`sel_write_enforce` to confirm
   a runtime byte and its offset (+0x00 vs +0x04); pick an aligned page VA preserving the
   neighbour flags; write; `cap_effective = g_blackval`; `setresuid`. Caveat: our pointer's
   byte4 is always 0xff, so only offset 0 is zeroable; and be ready within the enforcing
   re-lock window (<5 s).
2. **`cred->security := *(init_cred+0x78)`** (real tsec, first word odd) + `cap_effective` +
   `setresuid`. Read `init_cred+0x78` with the boot_id primitive (forked reader). Prevent the
   deferred `kfree(init_cred.security)` by keeping a resident child / `usage` bump.
3. **Write `{osid,sid}={1,1}` into the existing blob** + `cap_effective` + `setresuid`.
   Zero kfree risk, most widely proven, but needs a raw small-int write (Case-2 shape).
   Side-effect repair via `/proc/self/attr/{exec,fscreate,sockcreate} = u:r:kernel:s0`.
4. **`cred`/`real_cred := &init_cred` on a forked anchor** (kernel SID) then a legal
   `setresuid`. Needs the Case-2 raw write + pre-writer child; HKIP kills the anchor unless
   the final state goes through `commit_creds`.
5. **Fork-storm: credit the forker with `&init_cred`**, rely on `copy_creds` +
   `hkip_init_task`. Architecturally the only "born with the bit" route, unproven on-device.
6. **UMH via forged `work_struct`.** Most HKIP-clean; blocked on bootstrapping full RW.
7. **Complete fake cred on a held page** (pfem10/vivo), both cred and real_cred, then
   `setresuid` to launder. Template for "what a fake cred must contain".

Deprioritized / do not retry: AVC poisoning (denials not cached + needs heap RW), emptying
`security_hook_heads` (RO), writing `selinux_enforcing` as a *symbol* (it is a struct field).

---

## Appendix — reusable 4.14 offsets (cross-check; build-specific)

| Value | Source |
|---|---|
| `cred.uid=4, gid=8, suid=0xc, sgid=0x10, euid=0x14, egid=0x18, fsuid=0x1c, fsgid=0x20, securebits=0x24, cap_inheritable=0x28, cap_permitted=0x30, cap_effective=0x38, cap_bset=0x40, cap_ambient=0x48, security=0x78, size=0xA8` | OPPO 4.14 target.h; aresin; pfem10 (5.10) |
| `task.real_cred/cred/comm/pid/seccomp` | aresin 4.14.186, OPPO 4.14.180, CLT-AL01 (build-specific) |
| `selinux_state` (4.14) at `_text+0x25b19d8`; enforcing `+0x04` | OPPO 4.14 target.h:194-199 |
| `selinux_state` from `enforcing_setup` / `SELINUX_BLOB_SIZES` from `selinux_cred_prepare` ADRP | aresin PROGRESS.md:24-25 |
| `init_cred` (4.14.180) `+0x21af810`; `init_task +0x219df00` | OPPO target.h:41-47 |
| `CAP_FULL = 0x1FFFFFFFFFF` (5 words) | pfem10/vivo |
| `commit_creds` BUG_ON(cred!=real_cred); setresuid/setresgid exempt | pfem10 exploit.c:2459-2522 |

### Collection references (absolute paths)
- `ghostlock_pocs\GhostLock-OPPO-PCKM00\exploit\src\root.c`, `...\exploit\targets\oppo-pckm00\target.h`, `...\report.md`
- `ghostlock_pocs\pixel-ksu-root\cves\lib\root\{cred.c,selinux_state.h}`
- `ghostlock_pocs\GhostLock-H80GT\exploit\src\sysctl.c`, `...\targets\annap-AGT-AN00_*\target.h`
- `ghostlock_pocs\ghostlock-pfem10\src\core\{payload.c,exploit.c}`
- `ghostlock_pocs\ghostlock-a17\src\core\{umh_root.c,root.c,target.h}`
- `ghostlock_pocs\CVE-2026-43499-Neo11Plus\exploit\src\posture.c`, `...\docs\posture-enhancements.md`
- `ghostlock_pocs\cve-2026-43499-aak-an00\docs\02-提权链路与成功要素.md`
- `ghostlock_pocs\vivo-root-build\src\root.c`
- `ghostlock_pocs\CVE-2026-43499-root-KernelSU\src\root.c`
- `ghostlock_pocs\ghostlock-cve-2026-43499\exploit\NOTES_2026-09-21_adjtimex_rb.md`, `...\NOTES_L1_arm32_rbwrite.md`, `...\kernel\OPPO_SYMBOLS.md`
- `ghostlock_pocs\cve-2026-43499-honor\docs\report.md`
- `ghostlock_pocs\CVE-2026-43499_HW-CLT-AL01\source\src\target.h`
- `ghostlock_pocs\ghostlock-aresin\{PROGRESS.md,target.h}`
- `ghostlock_pocs\ghostlock-cve-2026-43499-4.19-k40\README.md`
- `ghostlock_pocs\s26-m1q-ghostlock-selinux\docs\M1Q_SELINUX_WRITE_FAIL_ROOTCAUSE.md`
- `ghostlock_pocs\IonStack_S21\RESEARCH.md`

### Bottom line
SELinux can be defeated WITHOUT replacing `cred->security`: either zero the authoritative
enforcing byte with an aligned-pointer write (OPPO 4.14 evidence puts it at
`selinux_state+0x04`), or point `cred->security` at an EXISTING real tsec whose first word is
odd (`init_cred.security`). Both are compatible with the pointer-write primitive and avoid
`selinux_cred_free`. Either, plus the verified `cap_effective` write and `setresuid(0,0,1)`,
ends in `commit_creds -> hkip_update_xid_root` — the only operation that sets the HKIP bit.
If full RW can be bootstrapped, the forge-and-swing UMH route is the most robust because it
never makes a task look root outside the kernel-domain worker that already holds the bit.
