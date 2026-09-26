# GhostLock Root Manager (MRX-W09)

A tiny, dependency-free Android "root manager" for the GhostLock uid-0 task.
It is a plain `Activity` with a **fully programmatic UI** (no XML, no resources,
no AndroidX, no Gradle, no native libs). Built by hand with `aapt2` + `javac` +
`d8` + `zipalign` + `apksigner`.

```
ghostlock_app/
├─ build.ps1                 # one-shot build (aapt2 -> javac -> d8 -> zipalign -> apksigner)
├─ debug.keystore            # generated on first build
├─ app/
│  ├─ AndroidManifest.xml
│  └─ java/com/ghostlock/manager/
│     ├─ MainActivity.java   # UI: status, run command, re-root, log pane
│     └─ RootClient.java     # channel A (socket) + channel B (file mail-slot)
├─ root/gl_poller.c          # THE ROOT-SIDE CODE TO ADD TO THE EXPLOIT
├─ tools/inject_dex.py       # puts classes.dex into the aapt2-linked APK
├─ analysis/parse_cil.py     # CIL resolver that produced the evidence below
└─ out/GhostLockManager.apk  # signed APK
```

## Deliverable

| item | value |
|---|---|
| APK | `F:\testtest\testenv\ghostlock_app\out\GhostLockManager.apk` |
| package | `com.ghostlock.manager` |
| activity | `com.ghostlock.manager.MainActivity` |
| minSdk / targetSdk | 26 / **27** |
| permissions | **none** |
| signatures | APK Signature Scheme **v2 + v3** (zipaligned) |

Install (do not run this from the build host if the device is off-limits — it is
provided as the required command):

```
adb install -r -g F:\testtest\testenv\ghostlock_app\out\GhostLockManager.apk
adb shell am start -n com.ghostlock.manager/.MainActivity
```

Rebuild:

```
pwsh -ExecutionPolicy Bypass -File F:\testtest\testenv\ghostlock_app\build.ps1
```

---

## 1. IPC channel: which one, and why

### Channel A — abstract socket `"\0gl_su"` — **DENIED, used only as a probe**

`untrusted_app*` has no `unix_stream_socket connectto` permission to the `shell`
domain. An exhaustive scan of `device_plat_sepolicy.cil` for
`unix_stream_socket (connectto)` rules whose source is `untrusted_app*` finds only:

```
runas_app, traced, displayserver, system_server   (plus hsensors / multimodalinputservice: read,write only)
```

and every rule whose **target** is `shell` has source `shell` only. There is no
`(allow untrusted_app* shell (unix_stream_socket (connectto)))`. So
`connect()` to `\0gl_su` from the app fails with `EACCES`. The app tries it anyway
(as required), logs the errno, and falls back — `RootClient.viaSocket()`.

### Channel B — file mail-slot — **CHOSEN**

The key fact is that **`shell` is a member of the `appdomain` typeattribute**
(`device_plat_sepolicy.cil:854`):

```
(typeattributeset appdomain (… shell system_app traceur_app untrusted_app untrusted_app_27 untrusted_app_25 …))
```

so every `appdomain`/`base_typeattr_2xx` allow also covers `shell`, and the union
of app + shell permissions on the candidate data types is:

| location | label | app (untrusted_app*) | root task (shell domain, uid 0) | verdict |
|---|---|---|---|---|
| `/data/local/tmp` | `shell_data_file` | read/open/dir-search (`:21397`,`:21398`) + **write to an existing file** (`:7312`, via `appdomain`) | full rwx (`:13938–13941`) | **PRIMARY** |
| app private dir | `app_data_file` | full rwx (`:7265`,`:7267`, via `base_typeattr_219`) | full rwx (`:7265`,`:7267`, same attribute) | fallback |
| `/sdcard` | `sdcard_type` (fuse) / `media_rw_data_file` | full rwx (`:7349–7352`, via `base_typeattr_222`) | full rwx (`:7349–7352`, same attribute) | fallback |

Attribute definitions (all include `shell` and all `untrusted_app*`):

```
:32025  base_typeattr_230 = (and (appdomain) (not (shell)))              # neverallow helper
:32041  base_typeattr_222 = (and (appdomain) (not (ephemeral_app isolated_app)))
:32047  base_typeattr_219 = (and (appdomain) (not (isolated_app)))
```

The important non-obvious rule is:

```
:7312   (allow appdomain shell_data_file (file (write getattr)))
```

Because the matching neverallow

```
(neverallow base_typeattr_230 shell_data_file (file (create setattr relabelfrom relabelto append unlink link rename)))
```

**does not list `write`**, an app really can overwrite an existing file in
`/data/local/tmp`, it just cannot `create`/`append`/`unlink`/`rename` it.
`base_typeattr_230 = appdomain \ shell`, so this restriction applies to apps.

Consequently the app must **not** use `O_CREAT`/`O_TRUNC`/`O_APPEND`. It opens the
pre-created slot with `RandomAccessFile("rw")` (`O_RDWR`, no truncate) and writes a
fixed-size, self-describing 4096-byte record. That is the whole trick.

### Slots actually implemented (tried in order)

1. `/data/local/tmp/gl_ipc` — root poller **pre-creates** `req`/`res` (mode 0666).
2. `<externalFilesDir>/gl_ipc` = `/sdcard/Android/data/com.ghostlock.manager/files/gl_ipc` — app creates it; no permission needed.
3. `<filesDir>/gl_ipc` = `/data/data/com.ghostlock.manager/files/gl_ipc` — app creates it.

Slots 2 and 3 exist so that the app still works even before the poller has
pre-created slot 1 (the app *can* create in its own dirs). The poller watches all
three. Channel A is always attempted first.

## 2. targetSdk = 27 (not 28)

* `targetSdk 27` maps to `untrusted_app_27`, which is **still in `appdomain`**, so
  its access to every slot above is identical to `untrusted_app` (targetSdk ≥ 28).
* It additionally grants `(allow untrusted_app_27 app_data_file (file (execute_no_trans)))`
  (`:21380`). The blanket `neverallow … app_data_file (file (execute_no_trans))`
  uses `base_typeattr_554` (`:31377`) which is defined to **exclude**
  `untrusted_app_27` and `untrusted_app_25`. This gives the app a possible
  independent path for the re-root button (stage a helper in its data dir and
  `exec` it). targetSdk ≥ 28 forbids this.
* `targetSdk ≤ 28` also keeps legacy external-storage semantics, so the `/sdcard`
  fallback slot needs no scoped-storage workaround.
* `targetSdk 25`/`untrusted_app_25` would also allow the exec, but 27 is the more
  modern of the two with no downside here.

`minSdk 26` is chosen so the app installs on Android 8+ (the API level where the
`u:r:shell:s0` + `appdomain` layout above is stable) and so v2 APK signing is
sufficient (no v1 JAR signature needed).

## 3. What must be added on the root side

Add `root/gl_poller.c` to the exploit (`ghostlock_mrx_e.c`). It runs **inside the
shielded uid-0 / `u:r:shell:s0` task** — the same task that already owns
`su_server()` (the one bound to `\0gl_su`). Call it right after the socket is
bound:

```c
gl_poller_prepare();                 /* mkdir slots, create req/res 0666 */
/* either block the thread:      gl_poller_loop();  */
/* or run it beside su_server:   pthread_t t; */
/*                               pthread_create(&t,NULL,gl_poller_thread,NULL); */
```

Condensed behaviour (full source in `root/gl_poller.c`):

```c
static const char *slots[] = {
  "/data/local/tmp/gl_ipc",
  "/sdcard/Android/data/com.ghostlock.manager/files/gl_ipc",
  "/data/data/com.ghostlock.manager/files/gl_ipc",
  "/sdcard/gl_ipc", NULL };

void gl_poller_prepare(void){            /* app cannot create in /data/local/tmp */
  for (i...) { mkdir(slots[i],0777); touch(slots[i]"/req",0666); touch(slots[i]"/res",0666); }
}

void gl_poller_loop(void){
  for (;;) {
    for (i...) {
      read slots[i]"/req" (4096);
      if (magic!="GLRQ" || seq==last) continue;      /* seq = 16 hex digits at [4..20) */
      cmd = NUL-terminated string at [20..);
      fork(); dup2(pipe,1/2); execl("/system/bin/sh","sh","-c",cmd); wait();  /* capture out+status */
      write "GLRS <seq>\n<status>\n<out>\n__GL_END__\n" to slots[i]"/.res.tmp";
      rename(".../.res.tmp", slots[i]"/res");        /* atomic publish */
    }
    usleep(100000);
  }
}
```

Standalone build (optional, for a quick test):

```
aarch64-linux-android26-clang -DGL_POLLER_MAIN -O2 root/gl_poller.c -o gl_poller
```

The poller is **additive**: the existing `\0gl_su` server and `/data/local/tmp/rsh`
keep working for `adb shell`. The poller only adds the file channel the app can use.

### Wire format

```
req (4096 bytes, little-endian-free text):
  [0..4)   "GLRQ"
  [4..20)  16 ASCII hex digits, sequence number
  [20..)   command, NUL-terminated, zero padded to 4096
res (text, atomically renamed into place):
  "GLRS <seq-hex>\n<exit-status>\n<combined output>\n__GL_END__\n"
```

## 4. Notes / what could not be determined

* **No device was touched** (per instructions). The APK is built and signature-
  verified locally; the end-to-end channel was not executed on hardware.
* **Firmware/policy mismatch:** `device_plat_sepolicy.cil` is from the extracted
  **11.0.0.210** firmware while the device runs **235**. The rules used here
  (`base_typeattr_219/222/230`, `appdomain`, `untrusted_app_all`) are core AOSP
  patterns and very unlikely to differ, but if the app is denied, confirm at
  runtime with `dmesg | grep avc` / `adb shell dmesg`.
* **Exact socket errno** on the app→`gl_su` `connect()` is assumed `EACCES`; if the
  exploit is not running it will instead be `ECONNREFUSED`. Either way the client
  falls back.
* The re-root button **cannot bootstrap root by itself**: it asks the running root
  task to execute `sh /data/local/tmp/reroot.sh`. If no root task is alive there is
  nothing to receive the request (the poller is the thing that runs it). Making the
  app self-sufficient would require porting the exploit to the app domain and
  using the targetSdk-27 `app_data_file execute_no_trans` allowance — a research
  item, not implemented.
* If a future variant runs the poller as **uid 2000** instead of uid 0, DAC would
  block it from the app's private dirs; the `/data/local/tmp` slot (files 0666)
  would still work. The current exploit task is uid 0, so all slots work.
* `/sdcard` slots depend on the volume being mounted and the user being unlocked;
  the primary `/data/local/tmp` slot does not.
