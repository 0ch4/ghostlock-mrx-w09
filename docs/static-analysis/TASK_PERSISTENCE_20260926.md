# MRX-W09 / GhostLock — Can root be re-established automatically after reboot?

Static analysis only (no adb, no device). Analyst session 2026-09-26.

## 0. Bottom line

**No fully-autonomous, on-device vector was found that re-runs our code at boot.**
Every boot-time actor that executes a program on this build resolves to a binary on a
read-only, verity-protected partition (`/system` or `/vendor`); no `on boot`/`on fs`/
`on property:…` action execs anything from a writable, attacker-controllable path, and
SELinux allows **only the `shell` domain** to execute our `/data/local/tmp` programs
(`shell_data_file`). No app domain, no `init`, no `vendor_init` and no Huawei `hw_*`/`hn*`
service can execute a `shell_data_file`.

Two caveats up front:

* **Firmware/device mismatch.** The extracted firmware is **11.0.0.210**
  (`[FIRMWARE]\MRX-W09\…`), the device in the notes is **11.0.0.235**. The 210
  `/system/bin/init` does **not** implement two Huawei custom commands used by the 210
  vendor rc (`load_filter_service`, `printservice`); the 235 init could differ. Anything
  that depends on a custom builtin must be re-checked on the device.
* The exploit's one-shot root is `uid 0` **in `u:r:shell:s0` with zero caps**, and the
  exploit endgame can additionally cede a **kernel SID** (`cred->security.sid=1`) for the
  duration of the process. Persistence options that require writing a privileged label are
  only reachable *during that rooted window*, and are marked as such below.

Practical fallback (best "one touch"): a persistent
`/data/local/tmp/reroot.sh` that runs the already-known 9y recipe, invoked with a single
`adb shell /data/local/tmp/reroot.sh` after boot. Details in §7.

---

## 1. Artifacts used (and how they were obtained)

| Artifact | Source | Notes |
|---|---|---|
| `plat_property_contexts`, `plat_file_contexts` | extracted `/system/etc/selinux/` (from `super_merged.img`) | EROFS, extracted with WSL `fsck.erofs` |
| `vendor_property_contexts`, `vendor_file_contexts`, `vendor_sepolicy.cil` | extracted `/vendor/etc/selinux/` (`vendor_a.erofs`) | same |
| `device_plat_sepolicy.cil`, `device_vendor_pub_versioned.cil`, `device_plat_file_contexts` | `binder_uaf\session_20260913\` | full compiled platform policy (2.0 MB) |
| `/init.rc`, `/system/etc/init/*.rc`, `/system/bin/init` | extracted `system.img` (3.27 GB, EROFS) | `system.img` carved from `super_merged.img` LP metadata |
| `init.kirin990.rc`, `init.platform.rc`, `fstab.kirin990`, 115 vendor `*.rc` | extracted `/vendor` (`vendor_a.erofs`) | |
| `MRX_W09_GHOSTLOCK_FACTS.md` | `binder_uaf\session_20260922\` | exploit-side ground truth |

Image carves: `super_merged.img` is an Android **sparse** image using a variant where
`next_chunk = chunk_hdr_offset + total_sz` (i.e. `total_sz` includes the 12-byte header).
LP metadata is at logical offset `0x3000`; partitions found: `system` (6 389 760 sectors
@ LBA 4096), `hw_product`, `cust`, `vendor`, `odm`.

---

## 2. Q1 — enumeration of boot-time actions that execute a program

### 2.1 System `init.rc` (extracted `\init.rc`, AOSP + Huawei)

| file:line | action | exec / start target | writable? |
|---|---|---|---|
| `/init.rc:37` | `on early-init` | `start ueventd` (→ `/system/bin/ueventd`) | no |
| `/init.rc:42` | `on early-init` | `exec_start apexd-bootstrap` (→ `/system/bin/apexd`) | no |
| `/init.rc:316-319` | `on load_persist_props_action` | `load_persist_props`; `start logd`; `start logd-reinit` | no |
| `/init.rc:342-377` | `on late-init` | `trigger fs/post-fs/post-fs-data/load_persist_props_action/zygote-start/early-boot/boot` | — |
| `/init.rc:384` | `on post-fs` | `exec - system system -- /system/bin/vdc checkpoint markBootAttempt` | no |
| `/init.rc:454` | `on post-fs-data` | `exec - system system -- /system/bin/vdc checkpoint prepareCheckpoint` | no |
| `/init.rc:472` | `on post-fs-data` | `exec -- /system/bin/fsverity_init` | no |
| **`/init.rc:708`** | `on post-fs-data` | `exec - system system -- /system/bin/tzdatacheck /apex/…/tz /data/misc/zoneinfo` | **arg 2 in /data (label `zoneinfo_data_file`)** |
| **`/init.rc:734`** | `on post-fs-data` | `exec - system system -- /bin/rm -rf /data/per_boot` | arg fixed; `/bin`→`/system/bin` |
| `/init.rc:741,748,755` | `on zygote-start` | `exec_start update_verifier_nonencrypted` | no |
| `/init.rc:891,896` | `vold.decrypt=trigger_restart*` | `exec_start update_verifier` | no |
| `/init.rc:944-951` | service `console` `/system/bin/sh` | domain `shell`, **`disabled`**, started only by `on property:ro.debuggable=1` (`:953-959`) | binary no; prop is ro / not settable |
| `/init.rc:961-963` | service `flash_recovery` `/system/bin/install-recovery.sh` | `class main`, `oneshot`; **file absent** from the image | n/a |

The `exec`/`exec_start` targets are all `/system` binaries. The only boot `exec` whose
*input* is writable is `tzdatacheck` reading `/data/misc/zoneinfo` (see §6, rank 4).

### 2.2 Vendor `*.rc` (`/vendor/etc/init/…`)

| file:line | action | target | writable? |
|---|---|---|---|
| `hw/init.kirin990.rc:498` | `on charger` | `mount_all /vendor/etc/fstab.${ro.hardware}` | fstab on ro `/vendor` |
| `hw/init.kirin990.rc:514-517` | `on fs` | `mount_all /vendor/etc/fstab.${ro.hardware}` | ro |
| `hw/init.kirin990.rc:1061` | `on data_ready` | `exec u:r:blkcginit:s0 root root -- /vendor/bin/sh /vendor/etc/blkcg_init.sh 0 0` | script on ro `/vendor`; args literal |
| `hw/init.kirin990.rc:1204-1209` | `on property:persist.sys.huawei.debug.on=0/1` | `chown/chmod /sys/class/sensors/sensorhub_dump` | not code |
| **`hw/init.kirin990.rc:1211-1212`** | `on property:persist.sys.load.svc=1` | `load_filter_service` | **no-op on 210 init (builtin absent)** |
| `init.platform.rc:26-27` | `on post-fs` | `sys_wp_init_action`; `start storage_info` | no |
| `init.platform.rc:409` | `on start_other_action` | `exec /system/bin/start_110x_service.sh` | script **absent** on 210 |
| `init.platform.rc:465-466` | `on property:ro.vendor.config.hw_vowifi=true` | `start iked` | ro prop |
| `init.ko.rc:11-14` | `on post-fs` | `exec u:r:vendor_modprobe:s0 -- /vendor/bin/modprobe -a -d /vendor/lib/modules hisi_dummy_ko.ko` | modules signed (`MODULE_SIG_FORCE=y`); dir ro |
| `init.device.rc` (`on early-boot`) | `start hwemerffu` | `/vendor/bin/hwemerffu` (root, oneshot) | no |
| `hisecd.rc:10-11` | `on boot` | `start hisecd` | no |
| `bsoh.rc` (`on boot`) | `start bsoh` | `/vendor/bin/bsoh` (system) | no |
| `init.charger.rc:24`, `init.hisi.usb.rc:*` | `on charger` / `sys.usb.config=*` | `exec_start apexd-bootstrap`; start fixed USB services | no |
| `init.manufacture.rc:92-95` | `on property:ro.runmode=factory` | `start fcs/fmd/multichannel` | ro prop |

Every service `path` in vendor (`197` service definitions) is under `/system` or
`/vendor`; the only non-`/system`,`/vendor` paths are `/sbin/{teecd,hilogcat-early,hwservicemanager,hdbd}`
(recovery/charger ramdisk, ro). **No service binary lives on a writable partition.**

### 2.3 System `etc/init/*.rc` (Huawei)

| file:line | action | target | writable? |
|---|---|---|---|
| `init.huawei.os.common.rc:17` | `on post-fs-data` | `start odmf-data-chgrp` → `/system/bin/odmf-data-chgrp.sh` (runs `find /data/odmf`) | script ro; chgrp only |
| `init.huawei.os.a15.rc:84-96` | `on property:persist.sys.fingersense=*` | writes sysfs only | not code |
| `init.huawei.os.a15.rc:98-102` | `on property:ro.config.hw_emcom=true` | `start emcomd` | ro prop |
| `aserviceproxyshell.rc:1-2` | `on property:persist.sys.pasteboard.distribute=true` | `start aserviceproxy_shell` → `/system/bin/sa_main /system/profile/aserviceproxy_shell.xml` | ro; prop type `pasteboard_dswitch_prop` (not shell-writable) |
| `heapprofd.rc:29` | `on property:persist.heapprofd.enable=1` | `start heapprofd` (`/system/bin`) | ro |
| `perfetto.rc:47-62` | `on property:persist.traced.enable=1` | `start traced`/`traced_probes` (`/system/bin`) | ro |
| `samba.rc:12-26` | services `smbd`/`nmbd` (class late_start, **disabled**, user `system`) | `/system/bin/smbd` references `/data/samba_server/lib` | on-demand only; no domain may `execute` `samba_data_file` (§6) |
| `hwrme.rc` | `on boot`: `mkdir /data/bitmaps`, writes `/data/bitmaps/uid` | `/system/bin/hwrme` (user system) | not code |
| `update_engine.rc`, `settings`, etc. | property-triggered fixed daemons | `/system` | no |

**Conclusion Q1:** no `on boot`/`on late-init`/`on fs`/`on property:…` action on this build
`exec`s or `exec_start`s a program whose binary or script lives on a writable partition.
The only writable *input* to a boot exec is `tzdatacheck`'s `/data/misc/zoneinfo` argument.

---

## 3. Q2 — persistent properties (`/data/property`) and `on property:persist.*`

**Loaded?** Yes. `init.rc`:
* `:316-319` `on load_persist_props_action` → `load_persist_props`
* `:366` `on late-init` → `trigger load_persist_props_action` (runs **before** `trigger boot`,
  `:376`). So a `persist.*` value present in `/data/property` at boot is visible to
  `on boot` actions.

**Any `on property:persist.*` trigger that runs an executable?** Exhaustive list from all
115 vendor rc + all system rc:

| rule | effect | code exec? |
|---|---|---|
| `hw/init.kirin990.rc:1211` `persist.sys.load.svc=1` → `load_filter_service` | custom builtin | **No — the 210 `/system/bin/init` has no `load_filter_service` symbol (`strings` count = 0), so it is an unknown command / no-op** |
| `hw/init.kirin990.rc:1204,1207` `persist.sys.huawei.debug.on` → `chmod` sysfs | chmod | no |
| `hw/init.kirin990.rc:1099…1202` `persist.sys.hyperhold.*` → `swapon_all` / `setprop` | swap | no |
| `init.huawei.os.a15.rc:84` `persist.sys.fingersense` → write sysfs | write | no |
| `hiview.rc:9,12`, `hilogcat.rc:100`, `atrace.rc:205`, `heapprofd.rc:29`, `perfetto.rc:47`, `aserviceproxyshell.rc:1` | start/stop fixed `/system` daemons | no (fixed binaries) |

**Can we set a persist property anyway?** No, by two independent gates:
1. `plat_property_contexts:61` maps `persist.sys.` → `system_prop`. The `shell` domain has
   no `(allow shell system_prop (property_service (set)))` (see the full shell allow list),
   so `setprop persist.sys.*` from our root shell is denied by the property service.
2. Writing the backing files directly is also denied: `property_data_file` is writable
   **only by `init`** (`(allow init property_data_file (file (ioctl read write create …)))`);
   `(neverallow base_typeattr_214 property_data_file (file (write create setattr relabelfrom
   append unlink link rename execute execute_no_trans)))`. `shell` has no
   `property_data_file` allow at all.

So Q2 = **loaded, but dead as a persistence channel** (both the property-set and the
file-write paths are SELinux-denied for `shell`).

> Note for a *future* rooted window: if the exploit endgame cedes **kernel SID** (as
> `--sid`/`--endgame4` attempt), a kernel-domain process could physically create
> `/data/property/persist.sys.load.svc` = `1`. That only becomes a vector **if the device's
> 235 init implements `load_filter_service`** (unknown; 210 does not). Treat as a
> one-shot test, not a proven path.

---

## 4. Q3 — which SELinux domains can `execute` a `shell_data_file`

Definitive scan over `device_plat_sepolicy.cil`, `vendor_sepolicy.cil`,
`device_vendor_pub_versioned.cil`, `pulled/vendor_sepolicy.cil`, `plat_sepolicy.cil`:

```
domains with execute on shell_data_file
  shell   file  ioctl read getattr lock map execute execute_no_trans open
```
(one single rule: `device_plat_sepolicy.cil:13940`; duplicated as
`_shell_allow_plat.txt:13`). Everyone else:

| domain | rule | meaning |
|---|---|---|
| `init` | `(allow init shell_data_file (dir (read create getattr setattr search open)))`, `(allow init shell_data_file (file (getattr)))` (`:12210-12211`); `neverallow init shell_data_file (dir (write add_name remove_name))` (`:12326`) | read/search + getattr only — **cannot read or execute** our binary |
| `vendor_init` | `neverallow vendor_init shell_data_file (lnk_file (read))` `:14775`, `(dir (write add_name remove_name))` `:14780` | no execute |
| `app_zygote` / `webview_zygote` | `neverallow … (file (… execute execute_no_trans open))` `:16722`, `:21705` | no |
| `untrusted_app` / `untrusted_app_all` / `platform_app` / `priv_app` / `system_app` | only `read/open/map`, all `neverallow` for `write/create/unlink` (`:21397`, `:19456`, `:20568`, `:24001`…) | no execute |
| `adbd` | `dir`/`file` read/write/create only (`:15212-15213`), no execute | no |
| `installd`, `dumpstate`, `system_server`, `radio`, `nfc`, `bluetooth`, `logserver`, `hwpged`, … | write/read only | no |

**Therefore an autostart app (any app domain), `init`, `vendor_init`, or any Huawei
boot-time daemon cannot launch a program stored in `/data/local/tmp`.** The only way an
app can run native code from `/data` is from a file *it creates itself* in its own
private dir (`app_data_file`) — see §4.1.

### 4.1 The one cross-domain exec path: `appdomain_tmpfs`, and the app-data exception

Shell-to-other cross reference (`shell` write/create types × domains with `execute`):
only **`appdomain_tmpfs`** appears — a dynamically typed **tmpfs** file
(`(typetransition <bluetooth|ephemeral_app|isolated_app|mediaprovider|network_stack|nfc|…> tmpfs file appdomain_tmpfs)`),
so it is **not persistent across reboot**.

For app private storage, the policy deliberately splits by target SDK:

* `untrusted_app_25`, `untrusted_app_27`: `(allow … app_data_file (file (execute_no_trans)))`
  (`:21355`, `:21380`) → **can** exec a binary in their own data dir.
* `untrusted_app` (targetSdk ≥ 28): no `execute_no_trans`; blocked by
  `(neverallow base_typeattr_554 app_data_file (file (execute_no_trans)))` (`:15525`).
* `untrusted_app_all` has `file (… execute …)` with `auditallow` (linker/`map` path), not
  `execute_no_trans`.
* `priv_app`/`ephemeral_app` are `neverallow app_data_file execute_no_trans`.

This is the sole reason an installed app is a *possible* boot-code-exec carrier (§6 rank 1).

---

## 5. Q4 — mounts: writable AND not `nosuid` AND not `noexec`

Source: `/vendor/etc/fstab.kirin990` (and device boot log):

```
/dev/block/by-name/splash2   /splash2  ext4  rw,nosuid,nodev,noatime,data=ordered,context=u:object_r:splash2_data_file:s0
/dev/block/by-name/userdata  /data     f2fs  nosuid,nodev,noatime,discard,inline_data,inline_xattr  (fileencryption,checkpoint)
/dev/block/by-name/cache     /cache    ext4  rw,nosuid,nodev,noatime,data=ordered
/dev/block/by-name/hisee_fs  /mnt/hisee_fs ext4 rw,noatime,barrier=1,context=u:object_r:hisee_data_file:s0  (wait,check,notrim,nofail)
/dev/block/by-name/misc      /misc     emmc  defaults
/dev/block/zram0             none      swap   defaults
# /system,/vendor,/product,/version,/cust,/odm : commented ext4 "ro" (mounted from super logical
#   partitions as EROFS under dm-verity; boot log: "erofs: cannot find valid erofs superblock",
#   "hw_init: SYS_WP is enable!"; init.rc:388 remounts rootfs "bind ro nodev")
overlay /system/product/{app,priv-app,etc/…} overlay ro,lowerdir=/preas/…:/system/product/…
/devices/... (sdcard/usbotg) voldmanaged=… (vold mounts public volumes nosuid,nodev)
```

Findings:
* **`/system` and `/vendor` are read-only** (EROFS + verity + `SYS_WP`); `/system` is also
  the source of the SELinux policy and cannot be edited by us.
* Mounts that are `rw`: `/splash2`, `/cache`, `/data`, `/mnt/hisee_fs`, `/misc`.
  `/splash2`, `/cache`, `/data` are all `nosuid` (setuid useless — consistent with the
  premise). **`/mnt/hisee_fs` is `rw` and has neither `nosuid` nor `noexec`** — the only
  such mount.
* But `/mnt/hisee_fs` is labelled `hisee_data_file`, and the policy gives it **only** to
  the kernel and `init` (mount), plus `dumpstate`/`logserver` `getattr`:
  `(allow kernel hisee_data_file_attr (file (ioctl read write create …)))`,
  `(allow init hisee_data_file_attr (filesystem (mount …)))`. **`shell` has no access
  rule to `hisee_data_file`/`hisee_data_file_attr` at all** — not even `search` — so we
  cannot write or execute a setuid helper there. Dead.
* `/misc` (`emmc defaults`) is mounted rw by the kernel's `emmc` fs_mgr special-case, but
  it is not a directory tree we can place executables in via the shell.
* The `overlay` lowerdir `/preas/…` is read-only and `/preas` is an empty dir in the
  system EROFS; the overlay itself is `ro`.

**Conclusion Q4:** there is **no mount that is simultaneously writable by our shell,
not `nosuid`, and not `noexec`** (under SELinux). Setuid persistence is impossible, and
no writable-mount-exec vector exists.

---

## 6. Ranked persistence vectors

### Rank 1 — Boot-completed app (targetSdk ≤ 27) that execs the exploit from its own data dir
* **What to write:** an APK installed with `pm install` (shell is allowed to install), plus
  a `BOOT_COMPLETED` receiver that copies `/data/local/tmp/ghostlock_mrx` (readable by apps:
  `untrusted_app_all` has `shell_data_file` `read/open`) into `getFilesDir()` and
  `Runtime.exec()`s it.
* **Required label:** the copy is created *by the app*, so it gets the app's
  `app_data_file` label (seapp/fscreate). The APK itself is `apk_data_file`.
* **Boot actor:** zygote/`system_server` broadcasts `BOOT_COMPLETED`; the app's receiver runs.
* **SELinux prereq:** app must map to `untrusted_app_25`/`untrusted_app_27`
  (`targetSdk ≤ 27`) so `execute_no_trans` on `app_data_file` is allowed
  (`:21355/:21380`); targetSdk ≥ 28 is blocked (`:15525`). DAC: `/data` is `nosuid` but not
  `noexec`, so exec is fine.
* **Blockers / uncertainty:**
  1. The exploit must be re-ported to run in an **app domain (uid = app)** — including the
     Mali/libc page-cache perf unlock (`inject_hook`) from an app process and the
     HKIP/SELinux endgame. Unproven; the current binary targets `shell`.
  2. A freshly installed app is in *stopped* state and will **not** receive
     `BOOT_COMPLETED` until launched once → needs one `am start` (one touch).
  3. Even if it runs, it yields root in the **app domain**, not `shell`; whether the
     endgame can cede kernel SID from there is unknown.
  → Best *potential* autonomous path, but a research project, not a turnkey vector.

### Rank 2 — No on-device actor; "one host command" re-root (recommended)
* **What to write:** `/data/local/tmp/reroot.sh` (+ keep `inject_hook`, `shellcode.bin`,
  `ghostlock_mrx` in `/data/local/tmp`; all persist across reboot).
* **Boot actor:** none. After boot, run **one** host command:
  `adb shell /data/local/tmp/reroot.sh`.
* **Prereq:** adb authorized (USB, or `adb tcpip`), device booted/unlocked.
* **Blockers:** not autonomous on-device; depends on host connectivity. Recipe (from
  `MRX_W09_GHOSTLOCK_FACTS.md` §9y):
  `inject_hook place 0x84000 0x244 0x7a3d8` → `inject_hook hook 0x7a3d4 0x84000` →
  `nohup bugreportz & sleep 20` → `inject_hook restore 0x7a3d4 0xd10403ff` → run the
  endgame (`paranoid` must read `-1`).

### Rank 3 — `persist.sys.load.svc` → `load_filter_service` (unverified / likely dead)
* **What to write:** `/data/property/persist.sys.load.svc` = `1`, label
  `property_data_file`.
* **Boot actor:** `init` `load_persist_props` (`/init.rc:316-319`, triggered at `:366`) →
  `on property:persist.sys.load.svc=1` → `load_filter_service`
  (`/vendor/etc/init/hw/init.kirin990.rc:1211-1212`).
* **Prereqs:** only `init` can write `property_data_file` (policy), and `shell` cannot set
  `system_prop`. So this can only be planted **during a kernel-SID rooted window**.
* **Blocker:** the 210 `/system/bin/init` contains **no `load_filter_service` symbol**
  (`strings` grep = 0) → unknown command / no-op. Must be re-tested on the device's 235
  init before believing it. (This is the single highest-value on-device check.)

### Rank 4 — `tzdatacheck` parses `/data/misc/zoneinfo` as init/system at post-fs-data
* **What to write:** a malformed tzdata blob in `/data/misc/zoneinfo`.
* **Boot actor:** `/init.rc:708` `exec - system system -- /system/bin/tzdatacheck … /data/misc/zoneinfo`
  (child stays in the **`init` domain**, uid `system`, because no seclabel is given).
* **Blocker:** `zoneinfo_data_file` writers are `tzdatacheck`/`system_server` only — `shell`
  cannot write it; and it requires a genuine parsing 0-day in `tzdatacheck`. Very low.
  Only plantable during a kernel-SID rooted window.

### Dead ends (verified, with the blocking rule)

| classic path | why it fails here |
|---|---|
| `init` execs a `/data` program | only `shell` may execute `shell_data_file` (§4); init gets `getattr` only |
| autostart app execs `/data/local/tmp/…` | apps cannot execute `shell_data_file`; targetSdk ≥ 28 cannot execute `app_data_file` (`neverallow base_typeattr_554 :15525`) |
| setuid binary on a writable, non-`nosuid` mount | only `/mnt/hisee_fs` is rw without `nosuid`; shell has **no** SELinux access to `hisee_data_file` |
| Magisk `/data/adb`, `/data/init.d`, `/data/misc` boot scripts | no rc imports/execs any of these; `init` only reads `/data/property` values |
| persistent property trigger → exec | shell cannot set `persist.*` (`system_prop`, policy) nor write `property_data_file`; the one exec-like trigger is a no-op builtin |
| kernel module from `/data` | `CONFIG_MODULE_SIG_FORCE=y`; `/vendor/bin/modprobe` only loads signed modules from ro `/vendor/lib/modules` |
| `su` | no `su` binary in system/vendor; `(neverallow domain su_exec (file (execute execute_no_trans)))` anyway |
| hotpatch / HwOUC from `/data/hotpatch`, `/data/update` | consumed by `system_server` Java (`hwEmui.jar`) with signature verification; no init exec; `hotpatch_file` has no `execute` rules |
| Samba dlopen from `/data/samba_server/lib` | `smbd`/`nmbd` are `disabled`/on-demand, run as `system`, and **no domain has `execute` on `samba_data_file`** |
| `run-as` | `runas_app` execs `app_data_file` only, and requires adb shell anyway; gives app uid, not boot activation |
| TEE/hisee, AVB/boot, `oeminfo` | block-device access denied to shell; verified boot / HKIP |
| `/system` remount rw | EROFS + verity + `SYS_WP`; no `CAP_SYS_ADMIN` |

---

## 7. Best "one touch" re-root path

1. Keep these files in `/data/local/tmp` (they persist across reboot):
   `ghostlock_mrx` (or `ghostlock_best`), `inject_hook`, `shellcode.bin`
   (`sc_perf_kaslr.bin`, 798 B, placeholder word `0x14000000` at file offset `0x244` —
   verify before use; the wrong blob hangs all of userspace, cf. FACTS §9x).
2. After each boot, one host command:
   ```
   adb shell /data/local/tmp/reroot.sh
   ```
   where the script runs the §6 rank-2 recipe and then the endgame.
3. If USB is not practical, enable `adb tcpip` and run the same one-liner from a host cron.
   There is **no device-side actor** that will do it without adb.

---

## 8. What is uncertain / could not be determined

* **Build 235 vs 210.** All rc/init/policy statements above are from the 210 firmware.
  The device runs 235. Specifically `load_filter_service` (and `printservice`) exist in
  210 rc but **not** in the 210 init binary; the 235 init may implement them. This is the
  main thing to test on-device.
* **`hisee_fs`** is `rw` without `nosuid`/`noexec`, but the policy grants shell nothing on
  `hisee_data_file`; I could not read the device's *runtime* mount table (no device), so
  the exact on-device flags (e.g. whether `fs_mgr` adds `nosuid` implicitly) were not
  observed directly — only the fstab and the ro/rw intent.
* **`appdomain_tmpfs`** path/location could not be pinned to a concrete directory (it is
  created by type transitions on `tmpfs`, not by a `file_contexts` path) — it is tmpfs, so
  it can never be a reboot-persistent store regardless.
* **`super_merged.img` sparse variant** required a custom parser (`total_sz` includes the
  12-byte chunk header); if a different tooling is used, be aware.
* **`install-recovery.sh`, `start_110x_service.sh`, `init.mygote64.rc`** are referenced by
  210 rc but absent from the extracted images; on the real 235 system they may exist
  (they would still be on ro `/system`).
* **Whether the exploit can be ported to an app domain** (rank 1) — not evaluated here;
  it is the only route that could become fully autonomous, so it is the best follow-up.
