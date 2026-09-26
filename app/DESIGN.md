# GhostLock Restore APK - design (fact-based)

Rules for this document: every statement is either **[MEASURED]** on the actual device or
**[TO CONFIRM]**.  Nothing may be assumed.  The device is used only for the final check.

---

## 0. Goal

After a cold boot, restore **root + the native GMS overlay** with the fewest user actions,
and show the state.  The restore itself is executed by the system's own bug-report path;
the app only **arms** the hook and **guides** the trigger.

---

## 1. What the app is (measured target/limits)

Package `com.ghostlock.manager`, `targetSdk 27` -> domain `untrusted_app_27`,
`minSdk 26`, no permissions declared.  (targetSdk 27 is deliberate: it is in `appdomain`
and additionally has `app_data_file execute_no_trans`, which is needed to run a helper
from its own data dir - 9an(157)D / the project README.)

### 1.1 CAN do - [MEASURED]

| capability | evidence |
|---|---|
| read `/system/lib64/libc.so` at `0x7a3d4` and `0x84000` | the app displayed `0b270014 [ON]` / `ff0304d1... [placed OK]` |
| read `/proc/sys/kernel/perf_event_paranoid` | the app displayed `perf : -1` then `3` after a reboot |
| read `/proc/mounts` | the app displayed `GMS : overlay 3/3` |
| stat + read a known `/data/local/tmp` file | the app displayed `shellcode.bin=576`; `/data/local/tmp/glroot.log` was shown by the app |
| overwrite an **existing world-writable** `/data/local/tmp` file | the app logged `shellcode.bin: synced (576 bytes)` |
| open Settings (Developer options) | `am start -a android.settings.APPLICATION_DEVELOPMENT_SETTINGS` worked from adb; from the app = **[TO CONFIRM]** |

### 1.2 CANNOT do - [MEASURED]

| limitation | evidence |
|---|---|
| create / unlink / rename anything in `/data/local/tmp` | neverallow (`base_typeattr_230 shell_data_file`); the app also gets EACCES on existing 0755 files |
| `mount(2)` | app seccomp-BPF is inherited across fork/exec and has no mount (9an(158)C) |
| send `android.intent.action.BUGREPORT` | needs `DUMP`; and no activity on this build resolves that action (this session) |
| connect to `\0gl_su` | no `(allow untrusted_app* shell (unix_stream_socket (connectto)))` |
| clear the payload's one-shot markers | it cannot unlink -> this MUST be solved in the payload/script (section 6) |
| install itself silently | `pm install` / `adb install` -> `INSTALL_FAILED_ABORTED: User rejected permissions` while Play Protect is on (this session) |

---

## 2. The verified restore (the thing the app must drive)

Cold boot, no PC, one `bugreportz` trigger - commit `e313059`:

```
arm : inject_hook place 0x84000 <size-4> 0x7a3d8 ; inject_hook hook 0x7a3d4 0x84000
      (payload = /data/local/tmp/shellcode.bin, 720 B, ph = 0x2cc)
trig: nohup /system/bin/bugreportz &
  +36s : perf=-1, overlays 3/3
         com.google.android.gms  PRIVILEGED
         com.google.android.gsf  PRIVILEGED
         com.android.vending     PRIVILEGED
```

[MEASURED] why one trigger is enough: it starts **two** processes, and the payload has one
branch per uid:

| process | uid | domain | may write perf | may exec shell_data_file |
|---|---|---|---|---|
| `bugreportz` (from `com.android.shell`) | 2000 | **u:r:shell:s0** | no | **yes (only domain that may)** |
| `dumpstate` (init starts it) | 0 | u:r:dumpstate:s0, CapEff=7fffffffff | yes | no |

[MEASURED] a capability-less uid-0 domain (installd, CapEff empty) also reaches the payload
and gets EACCES writing perf -> **the payload must write perf BEFORE claiming its one-shot**,
otherwise that domain locks out every capable domain and the exploit dies with
`[-] KASLR leak failed` (ghostlock_mrx_e.c:3365) after minutes.

[MEASURED] a **second exploit run in one boot resets the device** (9an(164)D).  So the app
must never arm twice in a boot, and the script must never start a second run.

---

## 3. App flow - "1 tap + 1 Settings tap"

```
Step 0  one-time provisioning (needs adb once, or a previous root)
        /data/local/tmp/shellcode.bin (0666), glboot.sh (0666), gms_setup.sh,
        ghostlock_e, gms_stage/...      <- the app can only OVERWRITE existing files
Step 1  [app]  ARM     run inject_hook place+hook, then read libc to prove it landed
Step 2  [user] TAP     the app opens Developer options; the user taps "Take bug report"
Step 3  [system]       the restore runs (~40 s; the framework restarts)
Step 4  [app]  CHECK   perf, overlays, PRIVILEGED, log
```

### 3.1 ARM (button 1)

1. read the payload **that is on the device** (`/data/local/tmp/shellcode.bin`): its length
   gives `ph = length - 4`, and its first 16 bytes are the expected cave content.
   (This is why the app must NOT use its bundled asset for `ph` - the payload changes.)
2. extract `assets/inject_hook` to `filesDir`, `chmod 700`, exec:
   `inject_hook place 0x84000 <ph> 0x7a3d8` then `inject_hook hook 0x7a3d4 0x84000`.
3. verify by reading `libc@0x7a3d4 == 0b270014` **and** `libc@0x84000 == payload[0..16]`.
4. if it did not land, retry - **[TO CONFIRM] the safe retry count.**  Measured so far:
   `place` + `hook` (2 Mali writes) is routine; the device reset was caused by
   `inject_hook restore` (a third write), never by place/hook (9an(164)D).  Until this is
   measured, the app must cap retries and prefer "tap the bug report again" over re-arming.

Never call `inject_hook restore`.

### 3.2 TRIGGER (button 2)

The app can only open Developer options; the user taps "Take bug report".
[TO CONFIRM] that this Settings path produces exactly the same two processes as
`adb shell nohup /system/bin/bugreportz &` (9an(160)C says yes; not re-measured here).
[TO CONFIRM] whether the app can start that screen directly (the action works from adb).

### 3.3 Optional auto-tap

An `AccessibilityService` could press the Settings item (survey's ranked candidate 1).
[TO CONFIRM] everything about it; out of scope until measured.

---

## 4. Status screen (all values already proven readable by the app)

```
payload : <device size> B        libc@0x84000 vs payload[0..16]  -> placed OK / NOT placed
hook    : libc@0x7a3d4           -> ON (0b270014) / off (ff0304d1) / unknown
perf    : /proc/sys/kernel/perf_event_paranoid   (-1 = stage 1 ran)
stage1  : /data/local/tmp/.glp0 exists?
stage2  : /data/local/tmp/.glp2 exists?
GMS     : count of upperdir=/data/local/tmp/glrt/gms in /proc/mounts  -> n/3
files   : each of shellcode.bin / glboot.sh / gms_setup.sh: size on device vs asset size
log     : tail of /data/local/tmp/glroot.log
install : package verifier setting, if the app ever needs to be reinstalled
```

Rules the status must follow (measured):
* `GMS 3/3` is the **only** trustworthy "restored" signal; the `dumpsys ... PRIVILEGED`
  flag can be stale (it read PRIVILEGED while overlays were 0/3).
* `hook ON` must be read from libc (page cache), never assumed from a previous run.

---

## 5. Failure handling (per measured hazard)

| symptom | measured cause | action shown to the user |
|---|---|---|
| arm does not land | the Mali write is flaky ([TO CONFIRM] rate) | offer one manual retry, then "reboot and try again"; never `restore` |
| stage 2 never runs | both markers present from an earlier boot; the app cannot unlink them | "reboot; the next boot self-heals" (only after the section 6 change) |
| exploit fails ("KASLR leak failed") | it ran without `perf=-1` | the script now refuses that; the app shows "stage 1 has not run yet - tap the bug report again" |
| the device resets during a restore | a second exploit run started in the same boot (9an(164)D) | do not arm again in the same boot; the app must disable ARM once the hook is verified ON |
| GMS/Play crash-loop at boot | Play self-updated GMS/Play into `/data/app`; without the overlay they lose their privileged base | show "run the restore"; recommend auto-update OFF once the Play Store is usable |
| app cannot be installed | Play Protect / Huawei confirmation | instruct: turn Play Protect scanning off, or install before signing in; keep `debuggable=false` |

---

## 6. Design requirement that is NOT implemented yet (must be one verified change)

The one-shot markers `/data/local/tmp/.glp0|.glp2` **survive reboots**.  A boot that ends
with both present cannot restore: the payload returns on EEXIST and nobody can unlink them
(the app cannot; installd cannot - no CAP_DAC_OVERRIDE).  Measured: both markers persisted
across a reboot and stage 2 never ran.

Required, as ONE change on top of `e313059`, then verified:
1. in the payload's uid-0 path, after a successful perf write, `unlink("/data/local/tmp/.glp2")`
   (a capable uid-0 process has CAP_DAC_OVERRIDE, so the stale path is freed for the shell
   domain);
2. in the script, clear the markers **only when the overlays are 3/3**; keep them otherwise,
   so a second stage 2 can never start a second exploit run.

---

## 7. Checklist for the single final device session

1. cold boot -> the app's STATUS shows hook off, payload placed, GMS 0/3.
2. app button 1 (ARM) -> the app reports hook ON; read libc from adb to confirm it agrees.
3. app button 2 -> Developer options opens; tap "Take bug report".
4. within 60 s the app's STATUS shows perf=-1 and GMS 3/3; `dumpsys` shows the three
   packages PRIVILEGED; the Play Store launches.
5. reboot once and confirm the section 6 change keeps the next boot able to restore
   (markers released).

## 8. Explicitly out of scope (needs its own measurement first)

* AccessibilityService auto-tap, BOOT_COMPLETED auto-arm, silent install.
* Any "one tap only" claim: the measured ceiling is **app + 1 Settings tap**.

---

## 9. Known APK issues and the roadmap to the goal (2026-09-26)

Goal: a **standalone (no PC), fast, repeatable** restore that also leaves real GMS/Play
working - reached by trial and error, but with every claim measured before it is relied on.

### 9.1 Known issue: "the UI becomes busy and never comes back" [CODE FACT]

```java
private volatile boolean busy;
onClick: if (!busy) action.run(); else log("(busy)");
bg():    busy = true; new Thread(...).finally { busy = false; }
```

`busy` is a **single global flag shared by every button**. [CODE FACT] Therefore one
background operation that never returns freezes the whole UI (every later tap logs
`(busy)`).  [NOT DETERMINED] which operation hung; the prime candidate is `exec()` waiting
for `inject_hook` to exit, but that has not been measured.  The only certain way to locate
it is the app's own logcat (`adb logcat -s GhostLock`): the last line printed is the step
that never finished.

Required fix (design): a per-action flag instead of a global one, an `exec` watchdog
(timeout + destroy of the child), and a UI that stays usable while a background op runs.

### 9.2 Known issue: the APK installed on the device predates the device-payload fix [FACT]

`/sdcard/Download/GhostLockManager.apk` was placed there **before** `readDevicePayload()`
was implemented.  That build derives `ph` from its bundled asset, so with today's 720 B
`/data/local/tmp/shellcode.bin` it would arm with `ph = 0x320` instead of `0x2cc`.
Rebuild + reinstall is required before the ARM path is tested at all.

### 9.3 Roadmap (each item = one change, one measurement)

1. **Marker lifecycle** (DESIGN §6): the payload unlinks a stale `/data/local/tmp/.glp2`
   after arming perf; the script clears the markers only at overlays 3/3.  Effect: every
   cold boot can restore; a second stage 2 can never start a second exploit run.
2. **App ARM path**: fix §9.1 (per-action busy + exec watchdog), rebuild, and verify with
   logcat that `place`+`hook` runs and the libc read-back shows `0b270014`.
3. **Trigger**: verify that Settings > Developer options > "Take bug report" produces the
   same two processes as `adb shell nohup /system/bin/bugreportz &`.
4. **GMS finishing touches** (all measured-able):
   * reinstall YouTube as part of the restore - a uid-2000 process in the shell domain holds
     INSTALL_PACKAGES, so the script can run the `cmd package install-create/write/commit`
     sequence (repo: `youtube_reinstall.sh`) and the `READ_GSERVICES` grant is recorded;
   * prompt the user to set Play auto-update OFF once the Play Store is usable.
5. Only after 1-4: claim "standalone one-tap (plus the one Settings tap)".

### 9.4 Things deliberately NOT claimed

* zero-tap (needs an AccessibilityService, unmeasured);
* fully silent install of the APK itself (the device refuses it while Play Protect is on);
* that the app can ever mount or unlink anything (both measured impossible).

---

## 10. Static policy cross-check (2026-09-26) and its caveats

Source: `ghostlock_pocs/STATIC_SELINUX_SURVEY.md` (statically derived from
`binder_uaf/session_20260913/device_plat_sepolicy.cil` and the vendor/versioned files).

| question | [STATIC] answer | agrees with measurement? |
|---|---|---|
| who may write `proc_perf` | only `init` (`:12163`) and `dumpstate` (`:25673`); read open to all (`:8293`) | installd failing perf -> **yes**; a `u:r:netd:s0` uid-0 process writing perf -> **NO** |
| `shell_data_file` `execute` | `shell` alone (`:13940`); `execmod` nobody | **yes** (stage 2 must be the shell domain) |
| `shell_data_file` create/unlink/rename | dumpstate, installd, shell, adbd (+init/vold create only) | not yet measured directly |
| `appdomain` write on `shell_data_file` | existing files only (`:7312`); create/unlink/rename neverallowed (`:7632-7638`) | **yes** (the app syncs shellcode.bin, gets EACCES on 0755 files) |
| `/dev` create/write | init / ueventd / vendor_init (+cust/kernel/fsck) only | **yes** (neither uid 0 nor uid 2000 could use /dev) |
| app reachability | app typetransitions reach only `rs` and `crash_dump` | consistent (the app cannot trigger or mount) |
| untrusted_app reading `proc_mounts` | denied | **NO** - the app displayed `GMS 3/3` from /proc/mounts |

**Why the two contradictions do not invalidate the design:** the extracted CIL is from
firmware **11.0.0.210** while the device runs **235** (already noted in the project README),
so the deployed policy is not byte-identical.  Conclusions that the design depends on:

1. The **perf-first rule** never has to know which domain may write perf: whichever domain can,
   proceeds; the rest return without consuming anything.  That is exactly why the netd/init
   ambiguity above is harmless.
2. Stage 2 stays gated on `u:r:shell:s0` (static + measured agreement).
3. Markers stay in `/data/local/tmp`; `/dev` is statically excluded.
4. Roadmap item 1 (the uid-0 path unlinking a stale `.glp2`) is statically viable -
   `dumpstate` has both the unlink allowance and CapEff=`0000007fffffffff` - but the payload
   must ignore an EACCES so that a capability-less hole (installd) stays harmless.
5. The app cannot do the restore itself (no reachable domain for perf/exec/mount).
