# TASK_SHELL_CAPSETUID — Does SELinux still deny `setresuid(0,0,0)` after `cap_effective |= CAP_SETUID`?

Date: 2026-09-26. **Static analysis only** (no adb, no device, no file edits).
Target kernel: `[WORKSPACE]\huawei_kernel_src\Code_Opensource\kernel` (Huawei MRX-W09 / Kirin 990, Linux 4.14.116, SELinux enforcing).
Policy artifacts: `binder_uaf\session_20260913\device_plat_sepolicy.cil` (MRX-W09 device policy), `session_20260824\plat_sepolicy.cil`, `pulled\vendor_sepolicy.cil`, `selinux_extract\allow_shell.txt`.

## Question 1 — Which SELinux hook(s) run on `security_capable()`?

`setresuid()` does `ns_capable(old->user_ns, CAP_SETUID)` → `security_capable()` → `call_int_hook(capable, ...)`.

`security/security.c:277-281`:
```c
int security_capable(const struct cred *cred, struct user_namespace *ns,
		     int cap)
{
	return call_int_hook(capable, 0, cred, ns, cap, SECURITY_CAP_AUDIT);
}
```

The SELinux hook registered on `capable` is **`selinux_capable`** and it is the only SELinux one:

`security/selinux/hooks.c:6454`:
```c
	LSM_HOOK_INIT(capable, selinux_capable),
```

`security/selinux/hooks.c:2246-2250`:
```c
static int selinux_capable(const struct cred *cred, struct user_namespace *ns,
			   int cap, int audit)
{
	return cred_has_capability(cred, cap, audit, ns == &init_user_ns);
}
```

(The full `capable` chain is `cap_capable` from `security/commoncap.c:1325` plus `selinux_capable`; `call_int_hook` stops at the first non-zero result. There is no Huawei `capable` hook in this tree — `security/hw_root_scan/sescan.c` only *reads* the hook list for diagnostics. `selinux_capset` / `selinux_capget` are separate hooks and do not run on `security_capable`.)

There is also **no SELinux `task_fix_setuid` hook** in this tree. `security_task_fix_setuid` (`security/security.c:1049`) is only implemented by commoncap (`security/commoncap.c:1337`), so no second SELinux check happens later in `setresuid()`.

## Question 2 — Does the hook call `avc_has_perm(..., SECCLASS_CAPABILITY, CAPABILITY__SETUID)`?

**Yes.** `selinux_capable` → `cred_has_capability`, `security/selinux/hooks.c:1726-1760`:
```c
static int cred_has_capability(const struct cred *cred,
			       int cap, int audit, bool initns)
{
	struct common_audit_data ad;
	struct av_decision avd;
	u16 sclass;
	u32 sid = cred_sid(cred);
	u32 av = CAP_TO_MASK(cap);        /* CAP_SETUID(7) -> 0x80 */
	int rc;

	ad.type = LSM_AUDIT_DATA_CAP;
	ad.u.cap = cap;

	switch (CAP_TO_INDEX(cap)) {       /* 7 -> index 0 */
	case 0:
		sclass = initns ? SECCLASS_CAPABILITY : SECCLASS_CAP_USERNS;
		break;
	case 1:
		sclass = initns ? SECCLASS_CAPABILITY2 : SECCLASS_CAP2_USERNS;
		break;
	...
	}

	rc = avc_has_perm_noaudit(sid, sid, sclass, av, 0, &avd);
	if (audit == SECURITY_CAP_AUDIT) {
		int rc2 = avc_audit(sid, sid, sclass, av, &avd, rc, &ad, 0);
		if (rc2)
			return rc2;
	}
	return rc;
}
```

Bit/name mapping (verified):
* `include/uapi/linux/capability.h:157` → `#define CAP_SETUID 7`
* `include/uapi/linux/capability.h:380` → `#define CAP_TO_MASK(x) (1 << ((x) & 31))` ⇒ `CAP_TO_MASK(7) = 0x80`
* `external/selinux/libselinux/include/selinux/av_permissions.h:526` → `#define CAPABILITY__SETUID 0x00000080UL`

For the adb shell, `current_user_ns()` is `init_user_ns`, so `initns == true` and the class is `SECCLASS_CAPABILITY` (not `cap_userns`). The requested permission is therefore exactly **`capability setuid`**, source = target = `cred_sid(cred)` (shell self).

## Question 3 — Does the shell domain have `allow ... capability setuid`?

**No. There is no `capability` allow of any kind for the `shell` domain.**

* `selinux_extract\allow_shell.txt` contains all 223 `(allow shell …)` rules extracted from the device policy, and **0 of them contain the string `capability`** (verified by grep and by `Select-String | Measure-Object` → 0).
* The **only** `shell self` rule in the device policy is:
  `device_plat_sepolicy.cil:14062`
  ```
  (allow shell self (process (ptrace)))
  ```
  (identical at `session_20260824\plat_sepolicy.cil:14062`). No `shell self (capability …)`, no `shell shell (capability …)`.
* The `shell` type is declared at `device_plat_sepolicy.cil:3398` (`(type shell)`).
* For contrast, neighbouring domains in the same file *do* carry the rule, e.g.
  * `device_plat_sepolicy.cil:15200` → `(allow adbd self (capability (setgid setuid)))`
  * `device_plat_sepolicy.cil:9654` → `(allow dumpstate self (capability (setgid setuid sys_resource)))`
  * `device_plat_sepolicy.cil:12212` → `(allow init self (capability (setgid setuid setpcap)))`
  The format is correct; `shell` is simply absent.
* No attribute-based grant was found either: searching `device_plat_sepolicy.cil` for `(allow (base_typeattr_…|domain|appdomain|coredomain|netdomain|halclientdomain) self (capability …)` returns nothing, and shell's attribute memberships (`domain` :786, `mlstrustedsubject` :850, `appdomain` :854, `netdomain` :858, `coredomain` :866, `halclientdomain` :948, `hal_atrace_client` :963) carry no capability allows. `pulled\vendor_sepolicy.cil` has no `(allow shell …)` rule at all.
* Cross-check: `ALTS_ROOT_CONTEXT_ESCALATION.md:198` already recorded "shell | *(no `capability` / `capability2` allow at all — only `(allow shell self (process (ptrace)))`)* | device_plat:14062".

So the required rule — `(allow shell self (capability (setuid)))` — does not exist anywhere in the artifacts.

## Question 4 — Is SELinux permissive for this check, or is the hook unregistered / returning 0?

Neither. The hook **is** registered (`hooks.c:6454`, object `selinux_capable`), and SELinux is **enforcing**:

* `security/selinux/include/avc.h:23-27`:
  ```c
  #ifdef CONFIG_SECURITY_SELINUX_DEVELOP
  extern int selinux_enforcing;
  #else
  #define selinux_enforcing 1
  #endif
  ```
* `arch/arm64/configs/merge_kirin990_defconfig:6250` → `# CONFIG_SECURITY_SELINUX_DEVELOP is not set`
  ⇒ `selinux_enforcing` is the compile-time constant `1`; SELinux is always enforcing and cannot be turned permissive at runtime via selinuxfs.
* `security/selinux/avc.c:1136-1138` computes `denied = requested & ~avd->allowed`; on denial `avc_denied()` (`avc.c:999-1013`) returns `-EACCES`:
  ```c
  if (selinux_enforcing && !(avd->flags & AVD_FLAGS_PERMISSIVE))
  	return -EACCES;
  ```
  Since `selinux_enforcing == 1` and shell is not a permissive domain, the check returns `-EACCES` → `ns_capable()` is false → `setresuid()` returns `-EPERM` and never reaches `commit_creds()`.

Empirical corroboration already on record: `binder_uaf\session_20260922\MRX_W09_GHOSTLOCK_FACTS.md:175-181` reports `capset(2)` with all-zero sets returns `-EPERM`, and `:178-181` concludes the only remaining denier is SELinux. (`selinux_capset` at `hooks.c:2227-2234` actually checks `process:setcap`, not `capability2:setpcap` as the note says — shell lacks that too — but the conclusion is unchanged.)

## Question 5 — Verdict

**NO.** With the process still in `u:r:shell:s0`, setting `cred->cap_effective |= CAP_SETUID` makes Linux's own `cap_capable()` pass (`commoncap.c:95`, `cap_raised(cred->cap_effective, cap)`), but `selinux_capable` → `cred_has_capability` then performs `avc_has_perm_noaudit(shell, shell, SECCLASS_CAPABILITY, CAPABILITY__SETUID)` and, because no `(allow shell self (capability (setuid)))` rule exists and SELinux is enforcing, it returns `-EACCES`. `ns_capable()` fails, `setresuid()` returns `-EPERM`, and no cred is installed.

**Caveat / the only way this becomes "yes":** if the endgame first re-points `cred->security` so `cred_sid()` returns a SID whose domain *does* hold the permission (e.g. sid 1 = kernel, the `--sid` design in `MRX_W09_GHOSTLOCK_FACTS.md` §9b), then the AVC pair becomes `kernel self:capability setuid` and the capability test can pass. That is a **different** question from the one asked (shell domain) and was never exercised on device (facts §9g.4). Note also that in this device policy the explicit `(allow kernel self (capability …))` rules (`device_plat_sepolicy.cil:12601,12617,12619,22927,22997`) do **not** include `setuid`, so even the kernel-SID route needs its own verification.

### Summary table

| item | result | source |
|---|---|---|
| SELinux hook on `capable` | `selinux_capable` | hooks.c:2246, 6454 |
| hook body | `cred_has_capability(cred, cap, audit, ns==&init_user_ns)` | hooks.c:2249 |
| AVC check for CAP_SETUID | `avc_has_perm_noaudit(sid, sid, SECCLASS_CAPABILITY, 0x80, 0, &avd)` | hooks.c:1753 |
| permission name | `CAPABILITY__SETUID = 0x80` | av_permissions.h:526 |
| `allow shell self (capability (setuid))` | **absent** | allow_shell.txt (0/223 contain "capability"); device_plat:14062 is only shell-self rule |
| SELinux mode | enforcing (compile-time `selinux_enforcing = 1`) | avc.h:26; defconfig:6250 |
| `setresuid(0,0,0)` after raising CAP_SETUID | **denied (-EPERM)** | avc.c:1007,1136-1138 |

### What was searched
* Kernel: `security/security.c`, `security/commoncap.c`, `security/selinux/hooks.c`, `security/selinux/avc.c`, `security/selinux/include/avc.h`, `kernel/sys.c`, `kernel/capability.c`, `include/uapi/linux/capability.h`, `arch/arm64/configs/merge_kirin990_defconfig`, `security/hw_root_scan/*`.
* Policy: every `*.cil` under `testenv` (glob) — in particular `binder_uaf\session_20260913\{device_plat_sepolicy.cil, device_vendor_pub_versioned.cil, pulled\plat_pub_versioned.cil, pulled\vendor_sepolicy.cil}` and `binder_uaf\session_20260824\{plat_sepolicy.cil, vendor_sepolicy.cil}` — plus `selinux_extract\allow_shell.txt`.
* Prior reports: `binder_uaf\session_20260922\MRX_W09_GHOSTLOCK_FACTS.md`, `binder_uaf\session_20260913\ALTS_ROOT_CONTEXT_ESCALATION.md`, `ALTS_CVE_SWEEP.md`. (`analysis_station\out\report_0*.md` were not needed; the on-point evidence is the root-context/ALTS reports.)

No live/on-device commands were run and no existing files were modified; this report is the only file created.
