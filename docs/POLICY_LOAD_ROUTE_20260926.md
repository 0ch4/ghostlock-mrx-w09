# Policy-load route to make `u:r:shell:s0` (type 1153) permissive — MRX-W09 (Kirin 990, EMUI 11, Linux 4.14.116)

Host-side static analysis only. No device, no adb, no existing files modified. This is the only
file created.

Sources used (all read-only):

* kernel: `[WORKSPACE]\huawei_kernel_src\Code_Opensource\kernel\security\selinux\` (the
  shipped Huawei source, incl. HKIP/kshield/prmem modifications)
* device policy (pulled): `[WORKSPACE]\binder_uaf\session_20260913\device_plat_sepolicy.cil`,
  `...\device_vendor_pub_versioned.cil`, `...\pulled\plat_pub_versioned.cil`,
  `...\pulled\vendor_sepolicy.cil`, `...\_shell_allow_plat.txt`, `...\_shell_allow_vendor2.txt`,
  `...\device_plat_file_contexts`, `...\pulled\vendor_file_contexts`
* binary policy: `[WORKSPACE]\binder_uaf\session_20260824\precompiled_sepolicy` (989,730 B)
* firmware: `F:\Dev\firmware\MRX-W09\extracted\` (`parts\vendor_a.erofs`, `parts\super_out\vendor.img`,
  `vmlinux.elf`)
* prior reports in `[WORKSPACE]\ghostlock_pocs\`: `TASK_POLICY_PATCH_20260926.md`,
  `ENDGAME_STRATEGY_20260925.md`, `BREAKTHROUGH_FULL_ROOT_20260926.md`, `SELINUX_PATH_RECON_20260924.md`

---

## 0. Executive answer — the load route is gated, and the gate is fatal

**`/sys/fs/selinux/load` cannot be written by the shell task, not because of DAC or caps, but
because `sel_write_load()` performs an SELinux check that no domain on this device passes.**

`security/selinux/selinuxfs.c:472-484`:

```c
static ssize_t sel_write_load(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	mutex_lock(&sel_mutex);
	length = avc_has_perm(current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__LOAD_POLICY, NULL);
	if (length)
		goto out;                    /* <-- shell dies here, before any byte is read */
```

* `sel_load_ops` has **no `.open`** (`selinuxfs.c:544-547`), so `open(O_WRONLY)` can never fail on
  SELinux — that is why the measured `open()` succeeds. It proves nothing about the write.
* The device policy grants the `security` class permission `load_policy` to **no domain at all**:
  the only *rule* mentioning it in the pulled policy is the neverallow
  `device_plat_sepolicy.cil:8525  (neverallow base_typeattr_215 kernel (security (load_policy)))`
  (plus the class-permission definition at `device_plat_sepolicy.cil:522` and a neverallow in the
  versioned file at `:5215`; no `(allow … (security (load_policy)))` exists anywhere).
  shell holds only `compute_av` and `check_context` on the `security` class
  (`device_plat_sepolicy.cil:19828,19834`; `_shell_allow_plat.txt:181,187`).
* `sel_write_load` has **no capability check** (source confirms only the AVC check); CAP_SYS_ADMIN
  in `cred->cap_effective` does not help. `kshield_chk_sel_write_load()`
  (`selinuxfs.c:495`) only fires when `current->inspected != 0`
  (`include/chipset_common/security/kshield.h:29-33`); it is not the blocker.
* Once the policy is loaded, `ss_initialized == 1`, so `security_compute_av()` takes the normal
  path (`services.c:1108`); only at **boot** (`ss_initialized == 0`) does the check short-circuit to
  `allowed = 0xffffffff` (`services.c:1140-1142`). There is no userspace reload path in normal
  operation.

**Consequence.** To write `/sys/fs/selinux/load` you must first make the shell **source type**
permissive (that is exactly what makes the `avc_has_perm` return 0 via `avc_denied()`
`avc.c:1007-1012`), i.e. you must already have done the in-memory `policydb.permissive_map` patch.
Loading therefore cannot be the *first* step. The load only adds two real things over the in-memory
patch: `avc_ss_reset()` flushes stale denied AVC entries (`services.c:2176`), and the permissive map
becomes kernel-owned/prmem-backed instead of living in the transient stamp window. Both are
*robustness* wins, not *cheapness* wins.

The only alternative bootstrap is zeroing `ss_initialized` (`services.c:101`, `selinux_wr`
section; written via `wr_assign`, `services.c:2092`), which is HKIP `.data_wr`-protected and
flagged unverified-risky (`TASK_POLICY_PATCH_20260926.md:38-44,306`). But zeroing it already grants
`allowed = 0xffffffff` for everything, so loading would again be moot.

**Cheapest reliable answer:** the in-memory `policydb.permissive_map` patch already documented in
`TASK_POLICY_PATCH_20260926.md` §2/§4/§7 (1–2 pointer writes). The loaded-policy route is the
runner-up, and its byte recipe is trivial once the gate is bootstrapped — documented below.

---

## 1. Precompiled binary policy: what exists and whether shell can read it

The firmware extraction `F:\Dev\firmware\MRX-W09\extracted\` has **no extracted /system or /vendor
tree** (only `parts\vendor_a.erofs`, `parts\super_out\vendor.img`, `parts\super*.img`, `vmlinux.elf`).
On-device paths therefore come from the pulled `file_contexts` and the prior pull.

| # | on-device path | SELinux label (evidence) | shell access (evidence) | notes |
|---|---|---|---|---|
| 1 | `/vendor/etc/selinux/precompiled_sepolicy` | `vendor_configs_file` via `/(vendor|system/vendor)/etc(/.*)?` (`device_plat_file_contexts:13`; the more-specific `/vendor/etc` rule overrides the generic `/(vendor|system/vendor)(/.*)?` → `vendor_file` at `:5`) | **READ** — `(allow domain vendor_configs_file (file (read getattr map open)))` (`device_plat_sepolicy.cil:8265-8266`; shell is in `domain`) | **binary policy**, the best exfil source. Measured `-rw-r--r-- root:root 989,730 B` in `TZDRIVER_HIJACK.md:2261-2268`. |
| 2 | `/odm/etc/selinux/precompiled_sepolicy` | `sepolicy_file` (`device_plat_file_contexts:817`) | **READ** — `(allow shell sepolicy_file (file (ioctl read getattr lock map open)))` (`_shell_allow_plat.txt:144`; `device_plat_sepolicy.cil:14075`) | second binary copy (odm variant) |
| 3 | `/system/etc/selinux/plat_sepolicy.cil` | `sepolicy_file` (`device_plat_file_contexts:816`) | **READ** (same rule as #2) | CIL text, 2,012,621 B |
| 4 | `/vendor/etc/selinux/vendor_sepolicy.cil` | `vendor_configs_file` (`device_plat_file_contexts:13`) | **READ** (domain rule #1) | CIL text, 555,373 B |
| 5 | `/vendor/etc/selinux/plat_pub_versioned.cil` | `vendor_configs_file` (`device_plat_file_contexts:13`) | **READ** (domain rule #1) | CIL text, 792,880 B |
| 6 | `/system/etc/selinux/plat_pub_versioned.cil` (and `.sha256` sidecars) | `system_file` (generic `/system(/.*)?`, `device_plat_file_contexts:65`) | **READ** — `(allow shell system_file (file (ioctl read getattr lock map open)))` (`_shell_allow_plat.txt:27`) | versioned CIL |
| — | `/sys/fs/selinux/policy` | — | **DENIED** (measured EACCES; `sel_open_policy` needs `security { read_policy }`, `selinuxfs.c:349-352`) | only `adbd` has `read_policy` (`device_plat_sepolicy.cil:15269`) |

**Verdict for Q1:** a precompiled **binary** policy exists and is readable by the uid-0 shell task.
The host copy at `binder_uaf\session_20260824\precompiled_sepolicy` is 989,730 B — exactly the
size measured on the device — and its header is valid for this kernel (see §2). It is therefore the
correct blob to patch and load. (The `vendor_a.erofs` / `vendor.img` images contain the file
**compressed**: a 20-byte header search finds no raw copy, and the single raw `0xf97cff8c` hit at
`0x2d01a002` is a false positive — its following `sym_num/ocon_num` words are invalid. Treat the
device pull, not the image, as the source of truth.)

The CIL files in `binder_uaf\session_20260824\` and `session_20260913\` are byte-consistent with each
other across sessions (`plat_sepolicy.cil` = `device_plat_sepolicy.cil`, 2,012,621 B;
`vendor_sepolicy.cil`, 555,373 B; `plat_pub_versioned.cil` = `device_vendor_pub_versioned.cil`,
792,880 B), so they describe the same build as the binary.

---

## 2. Binary policy format and the exact byte-level recipe

The device policy is a **version-30** (`POLICYDB_VERSION_XPERMS_IOCTL`,
`security/selinux/include/security.h:40`) libsepol image. Parse of
`session_20260824\precompiled_sepolicy`:

```
0x00  u32  magic      = 0xf97cff8c          (POLICYDB_MAGIC = SELINUX_MAGIC)
0x04  u32  strlen     = 8
0x08  "SE Linux"      (8 bytes, no NUL)      (POLICYDB_STRING)
0x10  u32  policyvers = 30
0x14  u32  config     = 0x1                  (POLICYDB_CONFIG_MLS -> mls_enabled = 1)
0x18  u32  sym_num    = 8                    (SYM_NUM, policydb.h:222)
0x1C  u32  ocon_num   = 7                    (OCON_NUM-2 = 9-2, policydb.h:234; compat entry
                                              POLICYDB_VERSION_XPERMS_IOCTL, policydb.c:171)
0x20  ebitmap policycaps : mapunit=64 highbit=64 count=1 startbit=0 map=0x27   -> ends 0x38
0x38  ebitmap permissive_map: mapunit=64 highbit=0  count=0                    -> ends 0x44
0x44  ... first symtab (nprim=5, nel=5) ...
```

Kernel read order is `policydb.c:2287-2408`: magic+strlen (`:2288`), "SE Linux" (`:2317`), version
and 4 table words (`:2337`), then **policycaps** (`:2365-2369`) then **permissive_map**
(`:2371-2375`) then the 8 symtabs. `ebitmap_read` is `ss/ebitmap.c:365-468`; the query is
`ebitmap_get_bit`, `ss/ebitmap.c:261-276` (cited in `TASK_POLICY_PATCH_20260926.md:208-222`).

### 2.1 ebitmap encoding (`ebitmap.c:365-468`)

Each bitmap = `{ u32 mapunit; u32 highbit; u32 count; then count × { u32 startbit; u64 map } }`.
The kernel requires `mapunit == BITS_PER_U64 (64)` (`:383`); it rounds `highbit` **up** to a multiple
of `EBITMAP_SIZE = 384` (`:390-392`); a node is 384-bit aligned via `startbit - startbit%384`
(`:433`). Bit `b` is `maps[(b-startbit)/64]` bit `(b-startbit)%64`.

### 2.2 Where type 1153 lives

Type 1153 (shell) falls in the 384-bit node `startbit = 1152 (0x480)`:
`1153-1152 = 1` → `maps[0]`, bit 1 → `map = 0x2`.

### 2.3 Exact recipe: add `shell` (1153) to `precompiled_sepolicy`

Current permissive_map is empty, so 12 bytes must be **inserted at file offset `0x44`**
(there is **no total-length / checksum field** in the header — `policydb_read` reads sequentially and
stops after the last struct, `policydb.c:2534-2539`; `policydb.len` is set from the write `count`,
`services.c:2111`). Resulting size = 989,730 + 12 = **989,742 B**.

```
file offset  size  new bytes (LE)       meaning
0x3C         4     81 04 00 00           permissive_map.highbit = 1153  (any value >= 1153 works;
                                         kernel rounds to 1536)
0x40         4     01 00 00 00           permissive_map.count   = 1
0x44        12     80 04 00 00           INSERT: entry.startbit = 1152
                   02 00 00 00 00 00 00 00   entry.map = 0x2  (bit 1 = type 1153)
```

`0x38` (mapunit=64) stays unchanged; everything from the old `0x44` onward shifts +12.

Python (host, no deps):

```python
d = bytearray(open(r"[WORKSPACE]\binder_uaf\session_20260824\precompiled_sepolicy","rb").read())
assert d[0:4] == bytes.fromhex("8cff7cf9"), "not a policy"
d[0x3c:0x40] = (1153).to_bytes(4,"little")           # highbit
d[0x40:0x44] = (1).to_bytes(4,"little")              # count
d[0x44:0x44] = (1152).to_bytes(4,"little") + (0x2).to_bytes(8,"little")  # insert node
open("precompiled_sepolicy.shellperm","wb").write(d) # 989742 bytes
```

Re-parsing the result gives `permissive_map: mapunit=64 highbit=1153->1536 count=1 startbit=1152
map=0x2` and `ebitmap_get_bit(1153) == 1`. `security_compute_av` then sets
`AVD_FLAGS_PERMISSIVE` for every shell-sourced decision (`services.c:1119-1120`), and `avc_denied`
returns 0 (`avc.c:1007-1012`) — for **every class**, not just capability.

### 2.4 What the kernel verifies on load (and what it does not)

`policydb_read` (`ss/policydb.c:2266-2544`) checks only:

1. magic `0xf97cff8c` (`:2293`),
2. `strlen == 8` and string `"SE Linux"` (`:2302,2326`),
3. `POLICYDB_VERSION_MIN <= policyvers <= POLICYDB_VERSION_MAX` = 15..31 (`:2343`;
   `include/security.h:44-45`),
4. existence of an exact compat entry (`:2378`, `policydb_compat[]`, `:94-180`),
5. `sym_num/ocon_num` equal the compat values (`:2386`),
6. full structural parse + `policydb_bounds_sanity_check` (`:2534`).

**There is no hash, checksum, signature or length field.** No AVB/Huawei hash check exists in
`security_load_policy` (`ss/services.c:2048-2194`). The only Huawei addition is
`kshield_chk_sel_write_load()` in `selinuxfs.c:495`, and that is `current->inspected`-gated.

The **reload** path (`ss_initialized == 1`, `services.c:2107-2194`) additionally:
* `policydb_load_isids` (`:2118`),
* `selinux_set_mapping` against the kernel `secclass_map` (`:2125`),
* `sidtab_map(clone_sid)` (`:2138`), then
* **`sidtab_map(convert_context)` (`:2148`)** — this re-derives every existing SID's context **by
  name** against the new policy (`convert_context`, `services.c:1864-1923`). If any user/role/type
  name used by a live SID is missing from the new policy, conversion fails and the whole reload is
  rejected. A copy of the *same* policy with only `permissive_map` changed therefore reloads
  cleanly; anything less does not (see §4).

---

## 3. CIL fallback: build `secilc` and rebuild the policy

Only needed if the readable binary policy is unavailable or cannot be trusted. Sources are present:

* `...\external\selinux\libsepol` (CIL lives in `libsepol\cil\src`)
* `...\external\selinux\secilc`
* NDK: `[WORKSPACE]\android-ndk-r20b\toolchains\llvm\prebuilt\windows-x86_64\bin\`
  (`aarch64-linux-android21-clang`, ... `-clang.cmd`), `...\prebuilt\windows-x86_64\bin\make.exe`

**sources of the CIL statement:** `(typepermissive shell_t)` is valid CIL
(`libsepol\cil\src\cil.c:167` `CIL_KEY_TYPEPERMISSIVE`, `android.c:400`); the base type is
`(type shell)` — **not** `shell_29_0` — at `device_plat_sepolicy.cil:3398`. So append the one line:

```cil
(typepermissive shell)
```

**Pitfall that dominates the build:** `libsepol\cil\src` ships `cil_parser.c` (pre-generated) but
**only `cil_lexer.l`, not `cil_lexer.c`** (verified: only `cil_lexer.h`/`.l` exist). The lexer must
be generated with **flex**; `bison` is not needed (parser is pre-generated). The installed
environment has `gcc` (`C:\msys64\mingw64\bin\gcc.exe`) and `wsl.exe`, but **no `make`, `flex` or
`bison` on PATH**; `msys64\usr\bin` has no `make.exe`. So a bare `make` will not work as-is.

Recommended build (WSL, easiest and most reproducible):

```bash
# in WSL Ubuntu
sudo apt-get update && sudo apt-get install -y build-essential flex make
cd /mnt/f/testtest/testenv/huawei_kernel_src/Code_Opensource/external/selinux/libsepol
make -j4                                  # builds libsepol.a / libsepol.so, generates cil_lexer.c
sudo make install PREFIX=/usr/local       # installs headers + libsepol.{a,so} + libsepol.pc
cd ../../secilc
make -j4                                  # links against the installed libsepol (-lsepol)
./secilc --help
```

msys2 alternative: `pacman -S --needed make flex gcc` then the same two `make`s.
aarch64 (device-side) alternative, only if you insist on compiling on the phone: build libsepol
first with the NDK (`make CC=<ndk>/aarch64-linux-android21-clang AR=... RANLIB=...`), then `secilc`
with the same `CC` and `LDFLAGS=--static -L<libsepol>`. This is pointless for our flow: the exploit
can read the precompiled binary, and the load gate (§0) is the blocker, not policy generation.

**Concatenate the same inputs the device ships** (all readable, §1):

```bash
secilc -m -M true -G -N -c 30 -o precompiled_sepolicy.shellperm -f /dev/null \
  device_plat_sepolicy.cil \
  plat_pub_versioned.cil \
  vendor_sepolicy.cil \
  shellperm.cil          # contains: (typepermissive shell)
```

* `-c 30` — match the device (version 31/`INFINIBAND` is also parseable, but 30 is what is loaded;
  `POLICYDB_VERSION_MAX=31`, `include/security.h:41,45`).
* `-m -M true` — the device policy is MLS (`config=0x1`).
* `-N` — disable neverallow checks, otherwise `(typepermissive shell)` plus any generated
  violations can fail the build; the device policy itself has neverallows (`:8525`).
* `-G` — expand generated attributes (matches Android's build and keeps the binary close to the
  device's).
* If the build reports undefined classes from `system_ext`/`product`/`odm`, add the corresponding
  `*_sepolicy.cil` — this device has product/odm (`device_plat_file_contexts`), and those files
  were not pulled. **This is the main reason the CIL route is riskier than patching the binary.**
* Endianness is not a pitfall (host x86-64 and aarch64 are both LE; the format is LE).
* Pitfall: rebuild output ordering/version may not byte-match the device's binary even when
  semantically equal — fine for loading (the reload path is name-based), but do not use it for
  differential comparison.

---

## 4. Is there something cheaper? (Q4)

* **Minimal / tiny policy — no.** `policydb_read` would parse it, but the live **reload** path
  requires `sidtab_map(convert_context)` (`services.c:2148`) to re-derive every live SID by name;
  a policy lacking the existing user/role/type names makes `convert_context` return `-EINVAL`
  (`services.c:1918-1923`), so the reload is rejected and the old policy stays. Even if it loaded,
  renumbering existing SIDs would mis-context every process. So the only policy that loads on a
  live system is a full copy with the same names.
* **Other selinuxfs nodes — no.**
  * `/sys/fs/selinux/enforce`: the `.write` handler is compiled out —
    `#define sel_write_enforce NULL` (`selinuxfs.c:167`), because `CONFIG_SECURITY_SELINUX_DEVELOP`
    is unset; reads return the constant 1. Same for `/sys/fs/selinux/disable`
    (`#define sel_write_disable NULL`, `selinuxfs.c:287`).
  * There is **no `permissive` (per-domain) node** in this 4.14 tree (grep of `selinuxfs.c` finds
    none), unlike newer Android kernels.
  * `booleans/*` and `commit_pending_bools` need `security { setbool }` — held by no domain
    (neverallow). `checkreqprot` is `(allow kernel self ...)` only (`device_plat_sepolicy.cil:12624`).
  * `/sys/fs/selinux/policy` read needs `security { read_policy }` (only `adbd`; `:15269`).
  * `access`/`create`/`relabel`/`member` are decision queries, not state changes; shell only has
    `compute_av`/`check_context`.
* **`selinux.reload_policy` property — unverified and does not help.** Prior work left it untested
  (`ALTS_PRIOR_WORK_LEADS.md:105`); `setprop` itself is SELinux-denied from shell
  (`TZDRIVER_HIJACK.md:2271`). Even if init honoured it, init reloads by writing the same
  `selinuxfs` node, and init also lacks `load_policy` — the same gate applies.
* **`ss_initialized = 0` (one zero write).** `int ss_initialized selinux_wr;` (`services.c:101`),
  written via `wr_assign` (`services.c:2092`) in the HKIP `.data_wr` region
  (`__start_data_wr=0xffffff800adc0000`, `ss_initialized=0xffffff800adc00a0`). A raw store is
  expected to fault / trip HKIP (`TASK_POLICY_PATCH_20260926.md:38-44,306`). **Unverified.** And if
  it did work it makes `security_compute_av` return `allowed=0xffffffff` for everything
  (`services.c:1108-1142`), which already achieves the goal — no load needed.
* **Persistence via `/sys/fs/selinux/` — none.** The policy lives in RAM; there is no writable
  enforcement control, and `/vendor/etc/selinux/precompiled_sepolicy` is read-only to shell
  (`vendor_configs_file` read-only to shell; shell has no write). A reboot reverts everything.
* **AVTAB allow injection — dominated.** ≥3 writes, needs the policy's bucket mask, and grants only
  one `(shell,security,SECCLASS_SECURITY,load_policy)` tuple; `permissive_map` grants all classes
  (`TASK_POLICY_PATCH_20260926.md:252-292`).

---

## 5. Oracle (verify from the same uid-0 shell task, no exec)

* **Load-specific (primary):** `n = write(load_fd, buf, len)`; `n == len` ⇒ the kernel accepted and
  installed the policy; `-1/EACCES` ⇒ the `load_policy` gate (expected today); other `-1` ⇒ parse
  failure (magic/version/structure).
* **Permission oracle (proves the loaded permissive bit):** `capset(NULL, all-zero)` (syscall 90) —
  baseline `-1/EPERM`, `0` once the shell **source** type is permissive
  (`ENDGAME_STRATEGY_20260925.md:124-126`). No exec, DAC-legal.
* **Cross-class oracle (no exec):** `open("/proc/self/attr/exec", O_WRONLY)` then
  `write(fd,"u:r:shell:s0",13)`. Baseline `-1/EACCES` purely from SELinux; `>=0` ⇒ shell permissive
  (`TASK_POLICY_PATCH_20260926.md:436-441`). `capset` and this path are uncached, so they observe a
  freshly installed `permissive_map`.
* **Definitive "the loaded policy has bit 1153":** after a successful load, `read_policy` is also
  granted (permissive), so `open("/sys/fs/selinux/policy")` now succeeds; read the image and check
  `0x38/0x3C/0x40/0x44/0x48` (`41`, `1153`, `1`, `1152`, `02 00…`). Before the load this open is
  `EACCES` (`selinuxfs.c:349-352`).
* **Caveat — AVC staleness:** pre-install denials are cached as `av_node.ae.avd.flags = 0` with no
  timeout (`avc.c:585-591,929-952,1130-1134`); the in-memory patch never clears them, whereas
  `security_load_policy` does (`avc_ss_reset`, `services.c:2176`). This is the one genuine reason to
  prefer the load route, and it is why the oracle must use an **uncached** tuple (`capset`, or a
  never-before-used class/target).

---

## 6. Ranked routes

| rank | route | what to write where | effort | blockers |
|---|---|---|---|---|
| **1** | **In-memory `policydb.permissive_map`** (no load) | 2 pointer writes: `policydb+0x1C8 ← V` (low32(V) ≥ 1153) and `policydb+0x1C0 ← fake ebitmap_node` with `startbit≤1153<startbit+384` and bit set | **low** — primitive already proven | window lifetime for the fake node; `permissive_map` offset must be confirmed on-device (`+0x1C0/+0x1C8` per `TASK_POLICY_PATCH_20260926.md` vs `+0x308/+0x310` in `ENDGAME_STRATEGY_20260925.md`); stale AVC |
| **2** | **Load patched full policy, bootstrapped by #1** | `write(/sys/fs/selinux/load, patched_precompiled, 989742)` where the blob has the 12-byte insert of §2.3 | **medium** — exfil 989 KB, patch 15 bytes, write | must first pass the `load_policy` AVC via #1 (so #1 is still mandatory); large vmalloc+parse; policy must be name-identical |
| **3** | `ss_initialized = 0` | zero write to `0xffffff800adc00a0` | low write, **high risk** | HKIP `.data_wr`; may fault/panic; and this alone already gives `allowed=0xffffffff` |
| **4** | CIL rebuild (`secilc`) + load | concatenate plat+versioned+vendor CIL `+ (typepermissive shell)`, `secilc -m -M true -G -N -c 30` | **high** | flex not installed; `system_ext`/`product`/`odm` CIL not pulled (completeness risk); output may not byte-match; still needs the §0 gate |
| **5** | AVTAB allow injection | `te_avtab` bucket + fake keyed node | high | ≥3 writes, needs hash mask, narrow — dominated by #1/#2 |
| — | `setenforce`/`enforce`/`permissive` nodes | — | — | write handlers compiled out / node absent / neverallow |

**Recommendation:** **Route 1** as the mechanism; add **Route 2** only if the transient-window
fragility of #1 is a problem and you want an AVC flush + kernel-owned map. The `/sys/fs/selinux/load`
route by itself is **not** viable and cannot be the first step.

**First measurement (one line, decisive, no state change):** as the uid-0 shell task, call
`write(open("/sys/fs/selinux/load", O_WRONLY), <any small buffer>, 1)` and print `errno`.
`EACCES` confirms the §0 gate and closes the naive route; any other result (e.g. `-EINVAL`) means
the AVC passed and would be a major contradiction to re-examine. This costs nothing and is safe:
the AVC check runs before `copy_from_user`/`security_load_policy` (`selinuxfs.c:481-507`).

---

## 7. Uncertainty / flags

1. **`permissive_map` in-memory offset is contradictory across reports** — `+0x1C0/+0x1C8`
   (`TASK_POLICY_PATCH_20260926.md`, re-derived from device disasm) vs `+0x308/+0x310`
   (`ENDGAME_STRATEGY_20260925.md`, static). Resolve with one `security_compute_av` disassembly
   before trusting route #1 at runtime.
2. **`security_load_policy` `convert_context` completeness** (§2.4/§4) is proven from source but was
   not executed; the patched-file reload is expected to succeed because names are unchanged.
3. **Host binary may not equal the currently loaded policy byte-for-byte** even though its size
   (989,730 B) matches the device pull and its header matches the kernel compat (30/MLS/8/7).
   Confirm by reading `/vendor/etc/selinux/precompiled_sepolicy` on-device and comparing the first
   0x44 bytes (and size). If the current policy were loaded from CIL without a matching precompiled
   file, the blob would still be name-compatible (reload is name-based), so the risk is limited.
4. **`.data_wr` writability** for `ss_initialized` is inferred from the section symbols/`wr_assign`
   machinery, not from PTE inspection — treat route #3 as unproven.
5. **CIL completeness** — `system_ext`/`product`/`odm` CIL were not pulled; the `secilc` route may
   fail on undefined classes/types unless those are added.
6. **Build tooling** — `flex` (and `make`) are absent from PATH; `cil_lexer.c` is not pre-generated.
   WSL or msys2 `pacman` is required. Not executed here (host-analysis only).
7. **`kshield`** is not a blocker *iff* our task has `current->inspected == 0`; this is a runtime
   property that was not measured.
