# LATEST CODE SUMMARY — GhostLock / MRX-W09 (CVE-2026-43499)

**Target:** Huawei MRX-W09 (MatePad Pro 10.8, 2019) · Kirin 990 (arm64) · EMUI 11 / build `11.0.0.235 (C635E3R1P6)` · Linux 4.14.116 (LTO/CFI, KASLR, Huawei HKIP) · serial `QBK6R20611000374`.
**Purpose:** ONE authoritative consolidation of the LATEST code state across all generations of scripts / payloads / exploit binaries.
**Method:** read-only host survey + read-only adb comparison. The only file written is this document.
**Date:** 2026-09-26.

## 0. Certainty legend and survey provenance

- **[MEASURED]** — observed on this session (host file hash / byte dump / device adb read) or a first-hand on-device measurement recorded in the cited evidence.
- **[DOC]** — asserted by a repository document (README / FACTS / CHANGE note); trusted but not re-measured here.
- **[UNCERTAIN]** — conflicting, stale, or not verified; treat as do-not-rely-yet.
- Hash tool: PowerShell `Get-FileHash -Algorithm SHA256` (host) and `adb shell sha256sum` (device).
- All sizes are bytes; all offsets hex. sha256 shown full for named binaries; a 12-hex prefix is used only inside the large payload appendix (still a `Get-FileHash` result).

**Authority anchors** [MEASURED]:
- Public main repo `F:\testtest\publish\ghostlock-mrx-w09` **HEAD `20b4825`** (`20b4825ea1c81adb995eaa525a4a795747f242e9`, 2026-09-26 15:59 +0900), remote `https://github.com/0ch4/ghostlock-mrx-w09.git`.
- Public GMS repo `F:\testtest\publish\ghostlock-mrx-w09-gms` **HEAD `6427925`** (`64279250b067fb6760981675dab4f96b3a49cfe7`, 2026-09-26 15:59 +0900), remote `https://github.com/0ch4/ghostlock-mrx-w09-gms.git`.
- Work repo `F:\testtest\testenv` **HEAD `3fda45a`** (`3fda45ad…`, 2026-09-26 16:32 +0900), **no remote**.
- Earlier docs dated themselves on `d602d4c` / `7e4c32c` / `33ccc57` / `058ad45`; those are **ancestors** of the current HEADs (see §8).
- Device reachable: `adb devices` → `QBK6R20611000374 device` [MEASURED]. HiSuite was running (`HuaweiHiSuiteService64`, pid 66384) but did **not** block adb.

---

## 1. TL;DR — the single current recommended file set

### (a) FAST ROOT-ONLY (uid0 / `u:r:shell:s0`, no GMS overlay)

| role | file | size | sha256 | notes |
|---|---|---|---|---|
| payload | `…\session_20260922\glboot_build\payload.bin` (= `publish\…\app\app\assets\shellcode.bin`) → device `/data/local/tmp/shellcode.bin` | 772 | `A28864BF90B85AC865A0E60967950E2DA4B1E4A36C0F4869BBC16D5499B353A1` | **ph = 0x300** |
| enabler | `inject_hook` (prebuilt) → device `/data/local/tmp/inject_hook` | 16512 | `28081EA685A5751F89243985A7676593A68B29156485BF24447E2F593B628A13` | identical in publish app assets + session_20260913 + ghostlock_app |
| exploit | `…\session_20260926_stabilize_oneshot\build\ghostlock_e` → device `/data/local/tmp/ghostlock_e` | 4118344 | `D6DF02FEBEB26C52D3848467A79AF673AC2A26DB46D49D5D8093B89ABFE0617B` | deployed/verified binary; **lacks the freeze-retry** (see §4/§9) |
| script | device `/data/local/tmp/glboot.sh` (FAST ROOT-only variant) — **device-only, not in any repo** | 2758 | `399DC0EC2E76DA0008B4B2D9EBC82EF083B2D84E58B8528BDD2F3EAD78EDC052` | pulled this session to temp; host copy of the frozen variant: session2022 `root_restore.sh` (2253, `C89DE630…`) |
| trigger | system `bugreportz` | — | — | ONE per boot |

**Exact parameters:** `sc_off=0x84000`, `ph=0x300` (payload 772 B → size−4), `back=0x7a3d8` (open64+4), `target=0x7a3d4` (open64[0]), `orig_insn=0xd10403ff` (`sub sp,sp,#0x100`), `hooked_insn=0x1400270b` (`b +0x9c2c`).

```
inject_hook place 0x84000 0x300 0x7a3d8
inject_hook hook  0x7a3d4 0x84000
nohup /system/bin/bugreportz &          # exactly one trigger
# verify: cat /proc/sys/kernel/perf_event_paranoid == -1 ; /data/local/tmp/su -c id == uid=0
```

### (b) FULL native-GMS restore (root + overlay 3/3 + PRIVILEGED×3)

| role | file | size | sha256 | notes |
|---|---|---|---|---|
| payload | same 772 B `shellcode.bin` (ph = 0x300) | 772 | `A28864BF90B8…` | |
| enabler | same `inject_hook` | 16512 | `28081EA685A5…` | |
| exploit | same `build\ghostlock_e` (or newest `build\ghostlock_e_lr2`) | 4118344 | `D6DF02FEBEB2…` | `--root-gms` is shield-free by default |
| restore script | `publish\ghostlock-mrx-w09-gms\scripts\gms_restore.sh` = `…-gms\scripts\glboot.sh` (= `session_20260926_stabilize_oneshot\scripts\gms_restore.sh`) → device `/data/local/tmp/glboot.sh` | 6191 | `6B023043DCFCBB94…` (full below §2) | header says "v6"; body already contains the v7 failed-run lock release |
| staging | `scripts/gms_setup.sh` | 1345 | `D3BE98209755BB3B…` | idempotent, takes overlay base as `$1` |
| framework restart (helper) | `scripts/gms_restart.sh` | 827 | `CB178E2219354FC4…` | `--root-gms` issues it itself |
| YouTube grant helper | `scripts/youtube_reinstall.sh` | 810 | `AB897349ABD3FEDA…` | run once while GSF is defined |
| one-command wrapper | `scripts/regms.sh` (payload-based) | 3317 | `11239F880919F3C4…` | fires the same bug-report path |

**Exact parameters:** identical offsets/instructions; `ph=0x300`. Staging layout `/data/local/tmp/gms_stage/{priv-app/{PrebuiltGmsCore,GoogleServicesFramework,Phonesky},permissions,sysconfig}`, plus **GSF also installed to `/data/app`** (persistent `READ_GSERVICES` definition) [DOC: gms README §9, CHANGE_06].
**Verify:** `grep -c "upperdir=.*/gms/upper-priv" /proc/mounts` == 3; `dumpsys package {com.google.android.gms,com.google.android.gsf,com.android.vending}` → `PRIVILEGED` ×3.

> **Recommended for a daily device:** do **not** repeat the overlay path (it damaged a PackageManager; gms `SAFETY_AND_RECOMMENDATION.md`). Use **microG (GmsCore) + Aurora Store + ReVanced**. Overlay = test-device / single-shot only.

---

## 2. Component inventory

### 2.1 Exploit binaries

| component (host path) | size | sha256 | generation / notes |
|---|---|---|---|
| `session_20260926_stabilize_oneshot\build\ghostlock_e` | 4118344 | `D6DF02FEBEB26C52D3848467A79AF673AC2A26DB46D49D5D8093B89ABFE0617B` | **deployed/verified**; == device `/data/local/tmp/ghostlock_e` and `ghostlock_app\assets\ghostlock_e`; built 12:45, **predates** `3878ebe` freeze-retry |
| `session_20260926_stabilize_oneshot\build\ghostlock_e_legalroot` | 4122536 | `C47A8B6D40CB238B61F248B0C2A857A0678A873B6B6C16109FD902E191CFE461` | CHANGE 01 (`--legalroot`) build [DOC] |
| `session_20260926_stabilize_oneshot\build\ghostlock_e_lr2` | 4135832 | `93F7EF62A03CCBBBCC4631344F8DCD60B53EC91428CAB128AE6F26BAA260DA43` | **newest build (17:45)**; contains the freeze-retry strings `root: park arm FAIL (retry)` / `root: park TIMEOUT (retry)` → closest to current source [MEASURED via strings] |
| `host_material\dev_ghostlock_e` | 4117576 | `00A3E280A212DB3C74F3D1C4B8F7233CFD5A6ED0FB9A35BC8E61018C5E8F413D` | dev material; older |
| `binder_uaf\session_20260922\ghostlock_mrx\ghostlock_e` | 4122472 | `2B7EF43A3458EC23893D941759D85F4A862FD997A48B5FFCE9ADC349D16426FA` | pre-`--root-gms` generation |
| `…\ghostlock_mrx\ghostlock_e_root` | 4121856 | `E503880105F295BCEEEB89C96F1A124D12CEEB080FCCABFD3C67AC39783BAFA2` | `--root` era |
| `…\ghostlock_mrx\ghostlock_e_gms` | 4117480 | `B44713E6FBCD7505D2E12CC41289E8FACB2D4B391C7545AA1D90A7C4610378EA` | first `--root-gms` era |
| `…\ghostlock_mrx\ghostlock_best` | 3962936 | `1A75E2F9FA4EE9D3B4E126FE338841394F8337890C6597ECC1FBF699AFC14B20` | early "best" |
| `…\ghostlock_mrx\ghostlock_e2` | 4068224 | `8E64B17E448BFCCB76D26F23874F96B81C3D36EA126E8196D67C1B1CFC233A4A` | intermediate |
| `…\ghostlock_mrx\ghostlock_mrx` | 3954912 | `C5DED57FA8456FF9489E557B0DD8F2F19A8BD0351CF237F22596A1058BFC5E58` | earliest working port |
| `…\ghostlock_mrx\ghostlock_mrx.sel` | 3967056 | `2264644D9614E91753E237522C659491F98AC295ABBADAF9C7FD285459480466` | intermediate |
| `…\ghostlock_mrx\ghostlock_mrx.new` | 3926008 | `712D38BB8145BF1378E71093B469CAFE0747FCD0E2BE50203BBA9ACF045AC485` | intermediate |
| `…\ghostlock_mrx\ghostlock_mrx.old` | 3948672 | `A426D64166236AEA6D5EA3AC06366B16455F9BDBCE4A4C0EF16C13B48F750C98` | intermediate |
| `…\ghostlock_mrx\ghostlock_e_freeze` (representative; `…_freeze2.._freeze11` also present) | 4098864 | `FFFD0746E50AE9B7EDBAC8C0AB7214C8E7185F240E61D75586C4AE73E6D71D6E` | experimental `--freeze` family [DOC] |
| `publish\ghostlock-mrx-w09\exploit\*` | — | **no binary** | source only: `ghostlock_mrx_e.c` 425651 `077DC6864B4E717B7797F2E873D840A84CD1E0DD9B275179A6B648ED4ED116A3`; `offset_mrx.h` 5278 `3A193E02BE89405F653F1701FF5CC781E90FC41765A9399BC78E504D7CF40601` |

`publish\exploit\ghostlock_mrx_e.c` sha256 == `session_20260926_stabilize_oneshot\src\ghostlock_mrx_e.c` sha256 (`077DC686…`) [MEASURED] → the published **source** is the latest (post-`20b4825`, incl. freeze-retry), but the newest **built** artifact is `ghostlock_e_lr2` (see §9 drift).

### 2.2 Payloads (`shellcode.bin` generations + `sc_*`)

Restore-path lineage (see §3 for the parameter table):

| component | size | ph | sha256 |
|---|---|---|---|
| `…\session_20260922\glboot_build\payload_verified_576.bin` | 576 | 0x23c | `0B29D954BFB1744B20D65E2E6DDC7C3C9A567D10B7B6497077A9FAA8EC0B67ED` |
| **688 B generation** — documented (`WORKING_PATH_WALKTHROUGH.md:159,179`, `ph=0x2ac`) | 688 | 0x2ac | **no artifact on disk** [DOC/UNCERTAIN] |
| `…\session_20260922\glboot_build\payload_verified_720.bin` | 720 | 0x2cc | `B7EA0D1066112F56CFA4C719D40139082B62B486C840AAA8FF0EF7BA52F22AC9` |
| `…\session_20260922\glboot_build\payload.bin` = `publish\…\app\app\assets\shellcode.bin` = device `shellcode.bin` | 772 | 0x300 | `A28864BF90B85AC865A0E60967950E2DA4B1E4A36C0F4869BBC16D5499B353A1` |
| **804 B generation** (`FACTS` 9an, `payload v7`, `ph=0x320`; `e313059` shrank 804→720) | 804 | 0x320 | **no artifact on disk** [DOC] |
| `…\session_20260922\sc_perf_kaslr.bin` = `shellcode_perf.bin` = `host_material\dev_shellcode.bin` = `session_20260915\sc_perf_kaslr.bin` | 798 | 0x31a | `C6A38CE01CE93222231BD74C7F0348636717A663434BC31651506E418E73EC71` |

First-16-byte check [MEASURED]: 576 / 720 / 772 / 798 all start `ff0304d1 e00700a9 e20f01a9 e41702a9` = exact open64-prologue replica → **verified** for all four required generations. (Older/other blobs use different prologue sizes: 702 B session_20260913 `shellcode.bin` = `ff0302d1…`; 1316 B `sc_perf6931_*` = `ff0308d1…`.)

### 2.3 Enabler

| component | size | sha256 | notes |
|---|---|---|---|
| `publish\…\enabler\inject_hook.c` (== `session_20260913\inject_hook.c` == `session_20260926_stabilize_oneshot\baseline\main\inject_hook.c`) | 7748 | `EC5646956644DFDD7A044B5F163F2ABE3D8D1CB89FB8C94CB9AA85DA67DD373E` | source |
| prebuilt `inject_hook` (publish app assets / ghostlock_app assets / `session_20260913\inject_hook`) | 16512 | `28081EA685A5751F89243985A7676593A68B29156485BF24447E2F593B628A13` | **all copies identical**; == device `/data/local/tmp/inject_hook` |

### 2.4 Scripts

| script | latest host file | size | sha256 | gen / notes |
|---|---|---|---|---|
| `glboot.sh` (FULL) | `publish\…-gms\scripts\glboot.sh` (= same as its `gms_restore.sh`) | 6191 | `6B023043DCFCBB94…` | v6/v7, byte-identical to `gms_restore.sh` (symlink-style alias) |
| `glboot.sh` (FAST root-only) | **device only** `/data/local/tmp/glboot.sh` | 2758 | `399DC0EC2E76DA0008B4B2D9EBC82EF083B2D84E58B8528BDD2F3EAD78EDC052` | pulled this session; **absent from every repo** [MEASURED] |
| `glboot.sh` (probe, obsolete) | `session_20260922\glboot.sh` (= baseline/gms + gms_repo) | 1230 | `C413A5382EF62C9E…` | glrt2 mount probe, not a restore script |
| `gms_restore.sh` (v6/v7, LATEST) | `session_20260926_stabilize_oneshot\scripts\gms_restore.sh` == `publish\…-gms\scripts\gms_restore.sh` | 6191 | `6B023043DCFCBB947FBA75B310F07C1A3F819E59819F19495900E16CE09446DB` | lock after perf gate; `btime`; base-agnostic; stage-1 `pkill -9 dumpstate`; failed-run lock release |
| `gms_restore.sh` (v5) | `session_20260922\gms_restore.sh` == `publish app assets` + `ghostlock_app app assets` | 6892 | `46F22D5C48B00B6A…` | v5 header; lock BEFORE perf gate (bug) |
| `gms_restore.sh` (baseline) | `session_20260926…\baseline\gms\gms_restore.sh` == `gms_repo\scripts\gms_restore.sh` | 4033 | `F2125A17E7ED38A0…` | oldest tracked |
| `root_restore.sh` | `session_20260922\root_restore.sh` == publish app assets | 2253 | `C89DE630DC9C67CE…` | SAFE root-only (no overlay, no framework restart) |
| `gms_setup.sh` (v6, LATEST) | `session_20260926…\scripts\gms_setup.sh` == `publish\exploit\gms_setup.sh` == `publish\…-gms\scripts\gms_setup.sh` | 1345 | `D3BE98209755BB3B…` | idempotent (`-s "$NEED"`), `B="${1:-…}"` |
| `gms_setup.sh` (older) | `session_20260922\gms_setup.sh` | 1546 | `E07B74FD3F2C99DB…` | |
| `gms_setup.sh` (app asset copy) | `publish app assets` / `ghostlock_app app assets` | 1421 | `7E08E0EFE7BD0E08…` | CHANGE-02-era variant |
| `gms_restart.sh` | `session_20260922\gms_restart.sh` == publish exploit + gms repo | 827 | `CB178E2219354FC4…` | |
| `regms.sh` (payload-based, LATEST) | `session_20260922\regms.sh` == `publish\…-gms\scripts\regms.sh` | 3317 | `11239F880919F3C4…` | uses `inject_hook` + `ghostlock_e --root-gms` |
| `regms.sh` (old GLMOUNT broker) | `publish\ghostlock-mrx-w09\exploit\regms.sh` | 3765 | `328FB60FD299A94A…` | **stale**: drives the `su` GLMOUNT broker (measured impossible) |
| `youtube_reinstall.sh` | `session_20260922\youtube_reinstall.sh` == gms repo | 810 | `AB897349ABD3FEDA…` | session-install split APKs |
| `glboot_exp01.sh` | `session_20260926…\scripts\glboot_exp01.sh` == publish docs/session_20260926 | 486 | `C531544F99427E1E…` | CHANGE-01 perf-only experiment |

¹ `publish\ghostlock-mrx-w09-gms\scripts\glboot.sh` and `…\scripts\gms_restore.sh` are byte-identical, sha256 `6B023043DCFCBB947FBA75B310F07C1A3F819E59819F19495900E16CE09446DB` (verified).

### 2.5 App

| component | size | sha256 | notes |
|---|---|---|---|
| `publish\ghostlock-mrx-w09\app\GhostLockManager.apk` | 41698 | `0C19A628264D4331B00FA47DDBB85E972010C1446FD991980077E20A1702A148` | == `ghostlock_app\out\GhostLockManager.apk` [MEASURED] |
| `testenv\ghostlock_app\GhostLockMRX.apk` | 1192648 | `225613A7FCC844A8137C3D854A36AE9E01D659B1C10784B9E37A161721A49837` | the shield-free/default `d6a2ec4` build |
| `publish\…\app\app\assets\inject_hook` | 16512 | `28081EA685A5751F89243985A7676593A68B29156485BF24447E2F593B628A13` | current |
| `publish\…\app\app\assets\shellcode.bin` | 772 | `A28864BF90B85AC865A0E60967950E2DA4B1E4A36C0F4869BBC16D5499B353A1` | current |
| `publish\…\app\app\assets\glboot.sh` / `gms_restore.sh` | 6892 | `46F22D5C48B00B6A…` | **STALE (v5)** vs current v6/v7 6191 |
| `publish\…\app\app\assets\root_restore.sh` | 2253 | `C89DE630DC9C67CE…` | fine (root-only, stable) |
| `publish\…\app\app\assets\gms_setup.sh` | 1421 | `7E08E0EFE7BD0E08…` | older variant |
| `testenv\ghostlock_app\assets\ghostlock_e` | 4118344 | `D6DF02FEBEB2…` | == deployed binary |

> App-asset drift [MEASURED]: the APK bundles `gms_restore.sh`/`glboot.sh` **v5 (6892 B)** while the repos carry **v6/v7 (6191 B)**. A rebuilt APK should embed the 6191 script. The `inject_hook` and 772 B payload assets are current.

### 2.6 Injected `.rc` block images (EROFS, all 4096 B, `evidence\erofs\`)

| file | sha256 | role |
|---|---|---|
| `perfetto_block_orig.bin` | `FFEC8DA918D01EACFED083464944B75EE3D3811054D1982E6D0CCBEF195E7441` | **stock** (revert) |
| `perfetto_block_new.bin` | `795AFC14AF9487330650B5372D21B5AB6E0F93C76A1FD87827558144C36BAE9E` | intermediate `/data/gls` variant |
| `perfetto_block_full.bin` | `F4C56FBCBC9357C1D659FEF1E00220DC3810DEB8C333245C9B6F26589D807675` | **current on-disk dangerous payload** (`mount` lines) |
| `perfetto_block_marker.bin` | `1BE82CA9FBA253332AC00E2EE61BBBEA061028B440647F8C19F6D03F990238FE` | **recommended disarm** (`setprop gl.boot.injected 1` only) |

Plan params [DOC, `inject_plan*.json`]: target `/system/etc/init/perfetto.rc`; nid `17754368`; `inode_off=568139776`; `inline_off=568139824` (`+48`); `size=2323`; `block_index=138706`; `super_phys_block=570236928`; `super_seek_4096=139218`; `verity_blocks_changed=1`; write `dd … of=/dev/block/sdd71 bs=4096 seek=139218 count=1 conv=notrunc`. Device `/data/local/tmp/perfetto_block_marker.bin` sha256 matches the host marker [MEASURED]. Whether the super block currently holds `full` or `marker` was **not** re-verified (needs root) [UNCERTAIN].

---

## 3. Payload parameter table

| size | ph = size−4 | sc_off | back | target | original insn | hooked insn | first 16 bytes |
|---|---|---|---|---|---|---|---|
| 576 | `0x23c` | `0x84000` | `0x7a3d8` | `0x7a3d4` | `0xd10403ff` | `0x1400270b` | `ff0304d1 e00700a9 e20f01a9 e41702a9` ✅ |
| 688 | `0x2ac` | `0x84000` | `0x7a3d8` | `0x7a3d4` | `0xd10403ff` | `0x1400270b` | (artifact not on disk) [DOC] |
| 720 | `0x2cc` | `0x84000` | `0x7a3d8` | `0x7a3d4` | `0xd10403ff` | `0x1400270b` | `ff0304d1 e00700a9 e20f01a9 e41702a9` ✅ |
| 772 | `0x300` | `0x84000` | `0x7a3d8` | `0x7a3d4` | `0xd10403ff` | `0x1400270b` | `ff0304d1 e00700a9 e20f01a9 e41702a9` ✅ |
| 798 | `0x31a` | `0x84000` | `0x7a3d8` | `0x7a3d4` | `0xd10403ff` | `0x1400270b` | `ff0304d1 e00700a9 e20f01a9 e41702a9` ✅ |
| 804 | `0x320` | `0x84000` | `0x7a3d8` | `0x7a3d4` | `0xd10403ff` | `0x1400270b` | (artifact not on disk) [DOC] |

- [MEASURED] open64 hook verification: pristine `libc@0x7a3d4 = ff 03 04 d1`; hooked `= 0b 27 00 14` (`0x1400270b`). `inject_hook place` computes the branch-back from `back − (sc_off+ph)`; `ph` must equal the payload's last-4-byte "back slot" offset = `size−4`.
- Cave budget [DOC `LIBC_CAVE_AND_PAYLOAD.md`]: 798 B and 848 B fire; **1072 B does not** → stay ≤ ~850 B. Current restore payload is well inside.
- The full long-tail list of every `shellcode_*.bin` / `sc_*.bin` under the targeted roots (≈110 files, each with size / ph / sha256-prefix) is in **Appendix A**.

---

## 4. Generation diffs — what changed and why

### 4.1 Payload generations

| gen | change | why |
|---|---|---|
| 798 B `sc_perf_kaslr.bin` | original perf-enabler payload; emits/parses perf, branches back | first payload that reliably fires in the dumpstate process [DOC] |
| 804 B "payload v7" | bigger, `ph=0x320` | `FACTS` 9an — still inside cave budget [DOC] |
| 576 B `payload_verified_576.bin` | `ph=0x23c` | early minimal enabler [DOC `e313059`] |
| 688 B | `ph=0x2ac`, `/dev`-priority markers + `/data` fallback | built but never cold-boot-tested; superseded [DOC, `WORKING_PATH_WALKTHROUGH.md:159,179`] |
| 720 B `payload_verified_720.bin` | `ph=0x2cc`; two-stage uid0/uid2000 guard; perf-first claim | `e313059` — "perf is armed by the capability check, not by arrival order" |
| **772 B** `payload.bin` (current) | `ph=0x300`; adds **one-restore-per-boot** behaviour via markers/scripts | `9e80b1a` changed payload.bin 720→772 |

Each size needs its own `ph`; a mismatch makes `place` write the branch-back over the wrong bytes.

### 4.2 Root endgame generations (shield → shield-free)

- **Old default (`--root-old` / `--root-old-gms`):** pid-0 shield (`task->pid=0`, offset `0x820`) + direct `cred` uid-zero (`cred+0x04`). Any fatal signal (`kill -9`, HKIP `force_sig(SIGKILL)`, OOM, framework kill) hits `do_exit`'s `if (!tsk->pid) panic("Attempted to kill the idle task!")` (`kernel/exit.c:786`) → **designed-in panic landmine** [DOC `TASK_PID0_RISK`].
- **New default (`--root` / `--root-gms`, shield-free):** shell-type permissive + `cred->cap_effective = CAP_SETUID` (HKIP cannot see `cap_effective`) + `setresuid(0,0,1)` → `commit_creds` → `hkip_update_xid_root` sets the **real-pid** HKIP bit → legal uid0, exits safely, no pid-0 task [MEASURED CHANGE01/02/03]. Integration promoted to default in `d6a2ec4`; `--root2`/`--root-gms2` were the working names in `660fe3d`/`67c02e8`.

### 4.3 `root_restore.sh` (old, safe, root-only) vs v6 `gms_restore.sh`

| aspect | `root_restore.sh` (2253 B) | v6 `gms_restore.sh` (6191 B) |
|---|---|---|
| scope | root only; no overlay, no framework restart | root + GMS overlay 3/3 + `ctl.restart zygote` |
| stage-1 `pkill -9 dumpstate` | no | **yes — in dumpstate's OWN domain** (`4186d1d`); the shell-domain kill is SELinux-denied *before* permissive ([CHANGE04]) |
| one-restore lock | none | atomic `mkdir .glboot.<btime>` (`9e80b1a`), **taken AFTER the `perf==-1` gate** (`8ecfb6e`) |
| lock key | — | `/proc/stat btime` (`8ecfb6e`), not `boot_id` (unstable across processes) |
| overlay idempotency | — | **base-agnostic** (`grep upperdir=.*/gms/upper-priv`, not a hardcoded `glrt` path) (`8ecfb6e`) |
| mounts | none | **all-or-nothing**: permissions + sysconfig FIRST, priv-app LAST, verify 3/3, `umount2` rollback, else skip framework restart (`95044bf`, `70c0a1c`) |
| AVC retry | — | yes (churn `avc_miss` ×8 then retry; stale deny can return EACCES despite permissive) (`70c0a1c`) |
| failed-run handling | — | `rmdir` the lock + clear markers on failure so a flaky run cannot brick the boot (`ac74d9c`) |
| overlays base | — | passed as `$1` from the exploit's actual tmpfs base (`67c02e8`); `gms_setup.sh` idempotent (no 135 MB recopy) |
| GMS staging + `/data/app` GSF | — | `gms_setup.sh` + install GSF to `/data/app` for persistent `READ_GSERVICES` (`CHANGE_06`) |

### 4.4 Cited commits

Work repo `F:\testtest\testenv`:
- `e313059` — "restore completes in 36 s – perf is armed by the capability check, not by arrival order" (payload.bin 804→720; adds 576; payload/script rework).
- `9e80b1a` — "One restore per boot: the boot-id gate stops the second exploit run" (payload.bin 720→772; adds 720; script gate).
- `f40cfe2` — FACTS 9an(167): GMS + Play restored; "the gl_su broker can never mount".
- `2b4a624` — FACTS 9an(166): safe PC-less root verified; adds `root_restore.sh`.
- `d602d4c` (main repo) — README §13: measured PC-less restore (+36 s) + traps.
- `d6a2ec4` — APK oneshot (per-action flags, exec watchdog), shield-free promoted to default `--root`/`--root-gms`; app assets synced.
- `4186d1d` — CHANGE 04 verified: fast/clean overlay; stage-1 dumpstate kill in its own domain; AVC retry; all-or-nothing.
- `8ecfb6e` — lock order fix (after perf gate, key=btime, base-agnostic idempotency), dumpstate abort, `root_cap_value` parks 40→12.
- `67ce9b1` — record artifact drift (pushed exploit lacked `--root-gms`) + CHANGE 01.
- `058ad45` (gms repo) — gms_restore.sh v6 + idempotent gms_setup + YouTube GSF fix.
- `d6a2ec4`, `67ce9b1`, `2b4a624`, `f40cfe2`, `9e80b1a`, `e313059`, `4186d1d`, `8ecfb6e` are all ancestors of work HEAD `3fda45a` [MEASURED `git log --all`].
- Later fixes [DOC]: `ac74d9c` (failed-run lock release), `1bee607` (never tmpfs over `/dev`/`/mnt`/`/data/local/tmp`), `3878ebe` (freeze-retry R), `c15c2a0`/`3fda45a` (raw-super persistence dead → per-boot only).
- Public main HEAD `20b4825` = freeze-park retry + `/dev`-safe targets + persistence conclusion. Public GMS HEAD `6427925` = gms_restore.sh v7 lock-release + phase timestamps.

---

## 5. Exact current recipes

### 5.1 FAST ROOT-ONLY (adb; authoritative)

```sh
# 0) push (files listed in §1a). Paths: B = ...\session_20260926_stabilize_oneshot\build
adb push "$B/ghostlock_e"        /data/local/tmp/ghostlock_e
adb push /data/local/tmp/inject_hook /data/local/tmp/inject_hook   # or push the prebuilt
adb push "$B/../...shellcode.bin" /data/local/tmp/shellcode.bin    # 772 B, sha256 A28864BF...
adb push "$B/../glboot_fastroot.sh" /data/local/tmp/glboot.sh      # the 2758 B fast script
adb shell chmod 755 /data/local/tmp/ghostlock_e /data/local/tmp/inject_hook /data/local/tmp/glboot.sh

# 1) arm (page-cache only; payload read from /data/local/tmp/shellcode.bin)
adb shell "rm -f /data/local/tmp/.glp0 /data/local/tmp/.glp2"
adb shell "/data/local/tmp/inject_hook place 0x84000 0x300 0x7a3d8"
adb shell "/data/local/tmp/inject_hook hook  0x7a3d4 0x84000"

# 2) exactly ONE trigger (starts bugreportz uid2000/shell + dumpstate uid0/all-caps)
adb shell "nohup /system/bin/bugreportz >/dev/null 2>&1 &"

# 3) verify
adb shell cat /proc/sys/kernel/perf_event_paranoid      # -> -1
adb shell /data/local/tmp/su -c id                      # -> uid=0(root) ... context=u:r:shell:s0
# do NOT run `inject_hook restore` in the same boot
```

### 5.2 FULL native-GMS restore (adb; authoritative)

```sh
# 0) push: 772 B payload / inject_hook / ghostlock_e / gms_setup.sh / gms_restore.sh AS glboot.sh
#    plus the persistent staging tree /data/local/tmp/gms_stage (135 MB) and the /data/app GSF copy
adb push <repo>\ghostlock-mrx-w09-gms\scripts\gms_setup.sh    /data/local/tmp/gms_setup.sh
adb push <repo>\ghostlock-mrx-w09-gms\scripts\gms_restore.sh  /data/local/tmp/glboot.sh   # 6191 B
adb shell chmod 755 /data/local/tmp/ghostlock_e /data/local/tmp/inject_hook /data/local/tmp/glboot.sh /data/local/tmp/gms_setup.sh

# 1) arm (identical offsets)
adb shell "rm -f /data/local/tmp/.glp0 /data/local/tmp/.glp2"
adb shell "/data/local/tmp/inject_hook place 0x84000 0x300 0x7a3d8"
adb shell "/data/local/tmp/inject_hook hook  0x7a3d4 0x84000"

# 2) ONE trigger. Stage1 = dumpstate uid0: write perf=-1, kill dumpstate (own domain).
#    Stage2 = bugreportz uid2000/shell: wait perf, take btime lock, run `ghostlock_e --root-gms`
#    (shield-free) which stages, mounts the 3 overlays, then `ctl.restart zygote`.
adb shell "nohup /system/bin/bugreportz >/dev/null 2>&1 &"

# 3) verify
adb shell "grep -c 'upperdir=.*/gms/upper-priv' /proc/mounts"          # -> 3
adb shell "dumpsys package com.google.android.gms | grep -i privileged"
adb shell "dumpsys package com.google.android.gsf | grep -i privileged"
adb shell "dumpsys package com.android.vending  | grep -i privileged"  # PRIVILEGED x3
```

One-command wrapper: `adb push scripts/regms.sh /data/local/tmp && adb shell /data/local/tmp/regms.sh` [DOC gms README §3].
PC-less: app → "★ 復元 (1操作)"; the AccessibilityService auto-taps 「バグレポートを取得」→「完全レポート」→「報告」[MEASURED CHANGE05]. Manual ceiling = app + 1 Settings tap.
After a successful run: `pm install -r -d /data/local/tmp/gms_stage/priv-app/GoogleServicesFramework/GoogleServicesFramework.apk` (persistent GSF), then install/update YouTube once; set Play auto-update OFF.

---

## 6. Traps (all measured; `publish\README.md` §13.2 and gms `README.md` §9)

1. **Capability-less uid-0 domain eats stage 1** — an `installd` uid-0 process reaches the payload but cannot write perf (EACCES) and has no `CAP_DAC_OVERRIDE`. → the payload MUST **write perf FIRST and only then claim** the one-shot; otherwise `[-] KASLR leak failed` (`ghostlock_mrx_e.c:3365`) and minutes are wasted. (Implemented in `glboot_payload.c`.)
2. **The `su` server cannot mount** — its `sh -c` child has `CapEff=0 / CapBnd=0xc0`; `mount(2)` → EPERM, and `mkdir` under `/data/local/tmp` (`shell:shell 0771`) → EACCES. Only the exploit's own uid-0 child (`ghostlock_e --root-gms`) can do the overlays. The old `publish\exploit\regms.sh` (GLMOUNT broker) is built on this dead assumption — **do not use it**.
3. **`/dev` cannot hold markers** — `tmpfs 0755 root:root`; uid-2000 is DAC-blocked and dumpstate is SELinux-blocked. Markers live in `/data/local/tmp` only.
4. **Markers survive reboots** — `.glp0`/`.glp2` on `/data` persist; a boot that ends with both present makes the payload return on EEXIST while nobody (app/installd) can unlink them. Mitigation: payload unlinks a stale `.glp2` after the perf write; script clears markers only at overlay 3/3 (or on a released failed run).
5. **NEVER two exploit runs in one boot** — measured to **reset the device** (double overlay). The `btime` lock + `--root-gms` design enforces this.
6. **`inject_hook restore` in the same boot is a hazard** — it is a *second* Mali page-cache write and was measured to reset the device (9an(164)D). The hook dies with the reboot; leave it.
7. **Stage-1 dumpstate kill must be in dumpstate's OWN domain** — the shell-domain `pkill dumpstate` is SELinux-denied before permissive; doing it late let the report drive loadavg to ~449 and starve the exploit's timing arms → Huawei watchdog reset (`InitWatchdog: init d-state`, `sp805-wdt`, hungtask whitelist `system_server/surfaceflinger/init`), **not** a pid-0 panic.
8. **Never mount the root tmpfs over `/dev`, `/mnt`, or `/data/local/tmp`** — a tmpfs over `/dev` hides devtmpfs nodes (`/dev/binder`, `/dev/dri`, …) → SurfaceFlinger/system_server hang → watchdog reboot. Only `/data/local/tmp/glrt{,2,3}` subdirs.
9. **Overlay upper MUST be tmpfs** — `/data` (f2fs) upper → EINVAL. All-or-nothing mounts; a lone priv-app overlay leaves GMS privileged without its allowlist → crash loop → black launcher.
10. **Play self-update is the real "corruption"** — after sign-in GMS/Play update into `/data/app`; the next cold boot has no overlay, so unprivileged `/data` copies demand privileged components (`INTERACT_ACROSS_USERS`, `MANAGE_USERS`) → crash loop. Keep auto-update OFF / use Aurora.
11. **APK install may be refused** — Play Protect / Huawei confirmation → `INSTALL_FAILED_ABORTED: User rejected permissions`. Disable Play Protect scanning, or install from `/sdcard`.
12. **Freeze PARK can miss** — the resident fake ebitmap node occasionally reads back garbage → permissive stays 0 → overlay fails; released by the failed-run lock release + the `3878ebe` freeze-retry.

---

## 7. Evidence matrix

| claim | verdict | source |
|---|---|---|
| 772 B payload, ph=0x300, first16 = open64 prologue | **verified** | `Get-FileHash` + byte dump this session; `evidence/CHANGE01_legalroot.txt:4` |
| 576/720/798 payloads + first16 | **verified** | `Get-FileHash`/byte dump this session |
| 688 B and 804 B generations existed | **doc only, artifact absent** | `WORKING_PATH_WALKTHROUGH.md:159,179`; `FACTS.md` 9an v7; `e313059` stat |
| `inject_hook` == device copy; 16512 B | **verified** | host hash + `adb sha256sum` |
| device `ghostlock_e` == `build\ghostlock_e` | **verified** | `adb sha256sum` = `D6DF02FE…` |
| device `shellcode.bin` == 772 B payload | **verified** | `adb sha256sum` = `A28864BF…` |
| FAST ROOT-only `glboot.sh` exists only on device | **verified** | `adb pull` → 2758 B, `399DC0EC…`; no host match |
| shield-free legal uid0, no pid-0 panic | **verified** | `evidence/CHANGE01_legalroot.txt` [A1][A2]; `CHANGE02_root2.txt` |
| full restore no-shield: overlay 3/3 + PRIVILEGED×3 | **verified** | `evidence/CHANGE03_rootgms2.txt`; `CHANGE04_fast_overlay.txt` |
| one-trigger +36 s (or ~5 s to 3/3) | **verified** | `e313059`; `CHANGE04`; `STATUS_20260926.md` |
| app oneshot + a11y auto-tap (~1 min) | **verified** | `evidence/CHANGE05_app_oneshot_success.txt` |
| YouTube `READ_GSERVICES` fix (GSF in `/data/app`) | **verified (fix), persistence re-test pending** | `evidence/CHANGE06…txt` |
| failed-run lock release works | **implemented + analysed** | `evidence/CHANGE07_lock_release.txt`; `ac74d9c` |
| 15-min no-watchdog stability | **unverified (open)** | `STABILITY_RUNBOOK_20260926.md` §1; `STATUS` "残" |
| watchdog trigger = PiP | **unverified hypothesis** | `STATUS` 訂正; `CHANGE06` follow-up |
| per-boot native-GMS overlay is unsafe for a daily device | **verified (caused a factory reset)** | gms `SAFETY_AND_RECOMMENDATION.md` |
| no reboot-persistent GMS route (per-boot only) | **doc, measured conclusion** | `STATUS_20260926.md` 追記; `3fda45a` |
| EROFS `.rc` injection feasible as fail-safe (`/data` gate) | **doc, plan only (P0)** | `CHANGE_08_EROFS_RC_INJECTION_PLAN.md`; `PERSISTENCE_SAFETY_ARCHITECTURE_20260926.md` |
| current on-disk super block = `full` (dangerous) vs `marker` | **unverified** | device marker file present; super not re-read (needs root) |
| `build\ghostlock_e` (12:45) includes freeze-retry | **NO — it does not** | strings: `root: park arm FAIL (retry)` present in `ghostlock_e_lr2`, absent in `ghostlock_e` |
| device `sys.boot.reason` | `kernel_panic,null` while uptime 15 min → contradictory | `getprop` this session [UNCERTAIN] |

---

## 8. Source list (paths, commits, remotes)

Local source trees (read-only survey):
- `F:\testtest\publish\ghostlock-mrx-w09` — main exploit + app + docs. HEAD `20b4825` (2026-09-26 15:59). remote `https://github.com/0ch4/ghostlock-mrx-w09.git`.
- `F:\testtest\publish\ghostlock-mrx-w09-gms` — GMS guide + scripts. HEAD `6427925` (2026-09-26 15:59). remote `https://github.com/0ch4/ghostlock-mrx-w09-gms.git`.
- `F:\testtest\testenv` — work repo. HEAD `3fda45a` (2026-09-26 16:32), **no remote**.
- `F:\testtest\testenv\session_20260926_stabilize_oneshot` — current session: `src/ghostlock_mrx_e.c` (== publish exploit source), `scripts/` (v6/v7 gms_restore, gms_setup, glboot_exp01), `build/` (ghostlock_e, _legalroot, _lr2), `evidence/` (CHANGE01..07, erofs blocks, bootloader, fec).
- `F:\testtest\testenv\binder_uaf\session_20260922` — `glboot_payload.c`, `glboot.sh` (probe), `gms_restore.sh` (v5), `gms_setup.sh`, `root_restore.sh`, `regms.sh`, `youtube_reinstall.sh`, `MRX_W09_GHOSTLOCK_FACTS.md` (387 KB), `WORKING_PATH_WALKTHROUGH.md`, `SUMMARY_20260922.md`, `ghostlock_mrx/` binaries, `glboot_build/`.
- `F:\testtest\host_material` — `dev_ghostlock_e`, `dev_shellcode.bin` (798), `mtg_stage`, Google APKs, `INSTALL_PLAN.ps1`.
- `F:\testtest\testenv\gms_repo` — mirror of the GMS repo (`scripts/glboot.sh` 1230, `gms_restore.sh` 4033, `regms.sh` 3317).
- `F:\testtest\testenv\ghostlock_app` — app build tree (`GhostLockMRX.apk`, `out/GhostLockManager.apk`, assets, `root/gl_poller.c`).
- `F:\testtest\testenv\binder_uaf\session_20260913` — `inject_hook.c` + prebuilt, pulled libc/sepolicy, diagnostic `shellcode_*.bin`/`sc_*.bin`.
- `F:\testtest\testenv\binder_uaf\session_20260915` — diagnostic `sc_*` probe payloads (perf/watchdog surveys).

Commit hashes named in this document (full where confirmed):
- main repo: `20b4825ea1c81adb995eaa525a4a795747f242e9` (HEAD), `33ccc57e6512fc5657ec2be8967f8ccc2185d1e8`, `d602d4c998118851daad32e860cd26c8a810402f`.
- gms repo: `64279250b067fb6760981675dab4f96b3a49cfe7` (HEAD), `058ad451932a84cef8413358fad1ca56ee1581f1`, `7e4c32c0891e1c4c7ebc1d99a515492b9177c521`.
- work repo: `3fda45ad…`, `c15c2a0`, `3878ebe`, `ac74d9c`, `1bee607`, `b3b479e`, `b2210a3`, `8aa2534`, `d5fbc8a`, `4186d1d`, `6ab49c6`, `2d194a0`, `70c0a1c`, `95044bf`, `8ecfb6e`, `d6a2ec4`, `67c02e8`, `62e14ec`, `660fe3d`, `7e1e21e`, `67ce9b1`, `362b309`, `9e80b1a`, `e313059`, `f40cfe2`, `2b4a624`, `f2182fc`.

---

## 9. Drift / action items (the honest gaps)

1. **Binary vs source drift [MEASURED]:** the latest exploit *source* (`ghostlock_mrx_e.c` `077DC686…`, == publish HEAD `20b4825`) includes the freeze-retry (`3878ebe`), but the deployed binary `build\ghostlock_e` (and device + app-asset copies, `D6DF02FE…`, built 12:45) **does not**. The only build that contains the retry is `build\ghostlock_e_lr2` (`93F7EF62…`, 17:45). **Action:** rebuild `ghostlock_e` from `077DC686…`, re-hash, push, and re-verify; then refresh the app asset `ghostlock_e`.
2. **App asset drift [MEASURED]:** the APK embeds `gms_restore.sh`/`glboot.sh` **v5 (6892 B)** while the repos carry v6/v7 (6191 B). Rebuild the APK with the 6191 script.
3. **Device `glboot.sh` [MEASURED]:** currently the FAST ROOT-only 2758 B variant that exists in **no repo**. Freeze it into the repo (it is the materially-latest fast path) or accept a documented divergence.
4. **`publish\exploit\regms.sh` [MEASURED]** still uses the dead GLMOUNT-broker path; replace with the gms-repo `regms.sh` (3317, `11239F88…`).
5. **Open — stability:** 15-min watchdog watch not passed; PiP hypothesis unconfirmed.
6. **Open — persistence:** no reboot-persistent GMS route; the EROFS `.rc` marker injection is planned/first-change only, and the on-disk super state is unverified.
7. **Payload archive gap:** the 688 B and 804 B generations are documented but absent on disk; archive them if reproducibility matters.

---

## Appendix A — full payload inventory (`*.bin`, restore + diagnostic)

All rows: `Get-FileHash -Algorithm SHA256` (12-hex prefix), `ph = size−4`. Files are for reference/diagnostics unless marked; **only the 772 B `shellcode.bin` (and its 576/720/798 kin) is on the restore path.**

```text
 size  ph        sha256(12)    path
  772  0x300  A28864BF90B8  publish\ghostlock-mrx-w09\app\app\assets\shellcode.bin
  517  0x201  850FC3F44E2D  testenv\binder_uaf\badspin_port\sc_dumpdev.bin
  492  0x1e8  B4EA26ED8FE9  testenv\binder_uaf\badspin_port\sc_exfil_lock.bin
  466  0x1ce  E7A2E9F488E4  testenv\binder_uaf\badspin_port\sc_exfil_open.bin
  592  0x24c  697297BCA783  testenv\binder_uaf\badspin_port\shellcode_kallsyms.bin
  364  0x168  5992A61D1CB3  testenv\binder_uaf\badspin_port\shellcode_kaslr_syslog.bin
  352  0x15c  80C1F7B56022  testenv\binder_uaf\badspin_port\shellcode_rootok_kaslr.bin
  560  0x22c  E4700013048D  testenv\binder_uaf\badspin_port\shellcode_rot.bin
  748  0x2e8  F2D22C8FDE3E  testenv\binder_uaf\badspin_port\shellcode_spinparse.bin
   88   0x54  D0D0648926EE  testenv\binder_uaf\session_20260824\shellcode_reaper.bin
  225   0xdd  FA96F2B3119F  testenv\binder_uaf\session_20260824\shellcode_v10.bin
  112   0x6c  C5BB8B147316  testenv\binder_uaf\session_20260824\shellcode_v11.bin
  331  0x147  89B84378E9C0  testenv\binder_uaf\session_20260824\shellcode_v12.bin
  525  0x209  87FBA771C5BD  testenv\binder_uaf\session_20260824\shellcode_v13.bin
  430  0x1aa  51455945DC5E  testenv\binder_uaf\session_20260824\shellcode_v13b.bin
  333  0x149  A5133B41B2EE  testenv\binder_uaf\session_20260824\shellcode_v13c.bin
  323  0x13f  5CC6636D5A54  testenv\binder_uaf\session_20260824\shellcode_v14.bin
  515  0x1ff  361A7BA65DB8  testenv\binder_uaf\session_20260824\shellcode_v15.bin
  336  0x14c  8DE7BBF7E0AF  testenv\binder_uaf\session_20260824\shellcode_v15b.bin
  315  0x137  9378ECD24800  testenv\binder_uaf\session_20260824\shellcode_v15d.bin
  317  0x139  C4F3BEB21BB5  testenv\binder_uaf\session_20260824\shellcode_v16.bin
  313  0x135  D1C1149DF536  testenv\binder_uaf\session_20260824\shellcode_v16r.bin
  155   0x97  08E2710801AB  testenv\binder_uaf\session_20260824\shellcode_v17.bin
  155   0x97  08E2710801AB  testenv\binder_uaf\session_20260824\shellcode_v17i.bin
  154   0x96  113C5DC37E15  testenv\binder_uaf\session_20260824\shellcode_v17k.bin
  196   0xc0  D0F3CFFE8454  testenv\binder_uaf\session_20260824\shellcode_v18.bin
  313  0x135  D1C1149DF536  testenv\binder_uaf\session_20260824\shellcode_v18r.bin
  311  0x133  08906F88D989  testenv\binder_uaf\session_20260824\shellcode_v21.bin
  323  0x13f  89AFA2384D67  testenv\binder_uaf\session_20260824\shellcode_v22.bin
  312  0x134  89AFFE4ABDE1  testenv\binder_uaf\session_20260824\shellcode_v23.bin
  304  0x12c  4CADC2D4EE71  testenv\binder_uaf\session_20260824\shellcode_v23d.bin
  184   0xb4  78E7FE742FB3  testenv\binder_uaf\session_20260824\shellcode_v25.bin
  192   0xbc  7511C4DD22CF  testenv\binder_uaf\session_20260824\shellcode_v26.bin
  336  0x14c  2C71ACD1C9A7  testenv\binder_uaf\session_20260824\shellcode_v27.bin
  332  0x148  A2D926DE69E3  testenv\binder_uaf\session_20260824\shellcode_v28.bin
  260  0x100  46DC44713B8A  testenv\binder_uaf\session_20260824\shellcode_v29.bin
  456  0x1c4  FEB208F8C0E3  testenv\binder_uaf\session_20260824\shellcode_v3.bin
  332  0x148  F9F09C676B2B  testenv\binder_uaf\session_20260824\shellcode_v30.bin
  264  0x104  B129AF49097F  testenv\binder_uaf\session_20260824\shellcode_v31.bin
  300  0x128  C51F3B39E786  testenv\binder_uaf\session_20260824\shellcode_v32.bin
  946  0x3ae  0A8BE8E9F882  testenv\binder_uaf\session_20260824\shellcode_v4.bin
  287  0x11b  40C60EB7F02D  testenv\binder_uaf\session_20260824\shellcode_v5.bin
  331  0x147  932EBA2249F6  testenv\binder_uaf\session_20260824\shellcode_v6.bin
  274  0x10e  0ED513E00258  testenv\binder_uaf\session_20260824\shellcode_v7.bin
  271  0x10b  CD7E12B9A09A  testenv\binder_uaf\session_20260824\shellcode_v8.bin
  247   0xf3  DA44647A3EFE  testenv\binder_uaf\session_20260824\shellcode_v8n.bin
  139   0x87  C76EA8A4D331  testenv\binder_uaf\session_20260824\shellcode_v9.bin
  505  0x1f5  563F330753E9  testenv\binder_uaf\session_20260904\tools\shellcode_w6v2.bin
  431  0x1ab  D726EA79CAC3  testenv\binder_uaf\session_20260911\shellcode_dubaid.bin
  428  0x1a8  8E88C052DC91  testenv\binder_uaf\session_20260911\shellcode_dubaid2.bin
   85   0x51  56E124E0933E  testenv\binder_uaf\session_20260911\shellcode_epoll_uncond.bin
  435  0x1af  BA3BB2F787E4  testenv\binder_uaf\session_20260911\shellcode_epoll.bin
  461  0x1c9  3AFFBF6C2BDA  testenv\binder_uaf\session_20260911\shellcode_hiai.bin
  315  0x137  BF4425B026C0  testenv\binder_uaf\session_20260911\shellcode_kallprobe.bin
  455  0x1c3  E2C860DA7A67  testenv\binder_uaf\session_20260911\shellcode_netd.bin
  447  0x1bb  49C715AD9ED0  testenv\binder_uaf\session_20260911\shellcode_probe3.bin
  352  0x15c  80C1F7B56022  testenv\binder_uaf\session_20260911\shellcode_rootok_kaslr.bin
  382  0x17a  EC9A721D00E7  testenv\binder_uaf\session_20260911\shellcode_rootok_kinfoprobe.bin
  355  0x15f  601FE7200D0A  testenv\binder_uaf\session_20260911\shellcode_syslog.bin
  383  0x17b  C9CF013175BF  testenv\binder_uaf\session_20260911\shellcode_syslog2.bin
  492  0x1e8  B4EA26ED8FE9  testenv\binder_uaf\session_20260913\sc_exfil_lock.bin
  466  0x1ce  E7A2E9F488E4  testenv\binder_uaf\session_20260913\sc_exfil_open.bin
  402  0x18e  A0FF208E9F6E  testenv\binder_uaf\session_20260913\sc_open.bin
  402  0x18e  9195DC57023C  testenv\binder_uaf\session_20260913\sc_openat.bin
  948  0x3b0  0192C8A177CB  testenv\binder_uaf\session_20260913\shellcode_capprobe.bin
  114   0x6e  6C600D822F15  testenv\binder_uaf\session_20260913\shellcode_epoll_init.bin
  118   0x72  B9A2666959DE  testenv\binder_uaf\session_20260913\shellcode_epollpwait_logd.bin
  325  0x141  A43D7E7F4748  testenv\binder_uaf\session_20260913\shellcode_ioctl_dev.bin
  135   0x83  BACAACD5E596  testenv\binder_uaf\session_20260913\shellcode_ioctl.bin
  568  0x234  34D980EAFF39  testenv\binder_uaf\session_20260913\shellcode_kallsyms.bin
  114   0x6e  4954DA7DA9C4  testenv\binder_uaf\session_20260913\shellcode_poll_init.bin
  118   0x72  4D1E9B6E9F8E  testenv\binder_uaf\session_20260913\shellcode_poll_logd.bin
  118   0x72  BCD41A2DFA3C  testenv\binder_uaf\session_20260913\shellcode_read_logd.bin
  560  0x22c  E4700013048D  testenv\binder_uaf\session_20260913\shellcode_rot.bin
  772  0x300  6F2D504B1FFA  testenv\binder_uaf\session_20260913\shellcode_spinparse.bin
  118   0x72  97F505FD0204  testenv\binder_uaf\session_20260913\shellcode_write_logd.bin
  702  0x2ba  67D7EB77A1B6  testenv\binder_uaf\session_20260913\shellcode.bin
  498  0x1ee  94492D6A014D  testenv\binder_uaf\session_20260915\sc_filnr_probe.bin
  398  0x18a  75A596D59143  testenv\binder_uaf\session_20260915\sc_hooktest.bin
  557  0x229  D2A3D9C3182A  testenv\binder_uaf\session_20260915\sc_kaslr_log.bin
 1063  0x423  836254898AA0  testenv\binder_uaf\session_20260915\sc_leak_survey.bin
  600  0x254  F3039FF2F222  testenv\binder_uaf\session_20260915\sc_netlink_probe.bin
  995  0x3df  1305DBCC43D8  testenv\binder_uaf\session_20260915\sc_oracle_probe.bin
 1485  0x5c9  0034052BD226  testenv\binder_uaf\session_20260915\sc_perf_adjacent.bin
  798  0x31a  C6A38CE01CE9  testenv\binder_uaf\session_20260915\sc_perf_kaslr.bin
 1316  0x520  475F8F13B679  testenv\binder_uaf\session_20260915\sc_perf6931_fire.bin
 1223  0x4c3  F23D1DA211F6  testenv\binder_uaf\session_20260915\sc_perf6931_probe.bin
 1316  0x520  1E7D1C875DE5  testenv\binder_uaf\session_20260915\sc_perf6931_safe.bin
  745  0x2e5  80FE694C0C72  testenv\binder_uaf\session_20260915\sc_pk64_safe.bin
 1812  0x710  B4EFC63DB2C5  testenv\binder_uaf\session_20260915\sc_probe4095.bin
 1404  0x578  2B96F47CEBBE  testenv\binder_uaf\session_20260915\sc_readsem_probe.bin
  671  0x29b  9AC45B75FB65  testenv\binder_uaf\session_20260915\sc_rlimit_probe.bin
  989  0x3d9  B8F4F4035317  testenv\binder_uaf\session_20260915\sc_setenforce.bin
 2001  0x7cd  D891674F0D45  testenv\binder_uaf\session_20260915\sc_sksec_sweep.bin
  795  0x317  F74C3D749AA3  testenv\binder_uaf\session_20260915\sc_sock_diag.bin
  813  0x329  138033B0E0AE  testenv\binder_uaf\session_20260915\sc_sysfs_probe.bin
  776  0x304  980A851583F4  testenv\binder_uaf\session_20260915\sc_sysrq_diag.bin
  817  0x32d  A4F752FD31F1  testenv\binder_uaf\session_20260915\sc_sysrq_kaslr.bin
  281  0x115  9D12E0488F7F  testenv\binder_uaf\session_20260915\sc_sysrq_only.bin
 1268  0x4f0  2D18230A8A19  testenv\binder_uaf\session_20260915\sc_trace_diag.bin
 1051  0x417  F64ACCFDEFAB  testenv\binder_uaf\session_20260915\sc_trace_probe.bin
  652  0x288  65804CC77DFA  testenv\binder_uaf\session_20260915\sc_vold_ks.bin
  652  0x288  B7EE4A7F3ECD  testenv\binder_uaf\session_20260915\sc_vold_ks.pid.bin
 1077  0x431  35B7FC32A69B  testenv\binder_uaf\session_20260915\sc_vold_ks2.bin
 1077  0x431  09A347759C61  testenv\binder_uaf\session_20260915\sc_vold_ks2.pid.bin
  576  0x23c  0B29D954BFB1  testenv\binder_uaf\session_20260922\glboot_build\payload_verified_576.bin
  720  0x2cc  B7EA0D106611  testenv\binder_uaf\session_20260922\glboot_build\payload_verified_720.bin
  772  0x300  A28864BF90B8  testenv\binder_uaf\session_20260922\glboot_build\payload.bin
  798  0x31a  C6A38CE01CE9  testenv\binder_uaf\session_20260922\sc_perf_kaslr.bin
  798  0x31a  C6A38CE01CE9  testenv\binder_uaf\session_20260922\shellcode_perf.bin
```

---

## Appendix B — host/device hash cross-check (read-only)

| artifact | host sha256 | device sha256 | verdict |
|---|---|---|---|
| `ghostlock_e` | `D6DF02FEBEB2…` | `d6df02febeb2…` | match |
| `inject_hook` | `28081EA685A5…` | `28081ea685a5…` | match |
| `shellcode.bin` (772) | `A28864BF90B8…` | `a28864bf90b8…` | match |
| `perfetto_block_marker.bin` (4096) | `1BE82CA9FBA2…` | `1be82ca9fba2…` | match |
| `glboot.sh` (FAST variant) | *(no host copy)* | `399DC0EC2E76…` (2758 B) | device-only |
| `rsh` (injected 4755 root shell) | — | `d4b3b9f7da66…` (303720 B, root:shell) | runtime artifact, not a source file |

Device state at survey time [MEASURED]: `/data/local/tmp` contains `ghostlock_e`, `inject_hook`, `shellcode.bin` (772), `glboot.sh`, `rsh`, plus markers `.glp0`/`.glp2`, lock dir `.glboot.1790428996`, logs `glroot.log`/`gl.klog`, `rooted.txt`. Device files: `ghostlock_e` mtime 12:45 (matches host build time), `inject_hook` 09:56, `shellcode.bin` 11:34. adb remained responsive; no state-changing adb command was issued.
