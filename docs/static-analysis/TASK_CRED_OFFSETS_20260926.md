# TASK: `struct cred` field offsets + allocation size for MRX-W09 (Kirin 990)

Host-side static analysis only. No device / adb / runtime access was used.
All offsets below were read **directly out of the device's own kernel image**,
not from generic headers. The shipped Kirin-990 source tree was used only as a
cross-check.

- Device image: `[FIRMWARE]\MRX-W09\extracted\vmlinux.elf`
  (ELF64 LE aarch64, 61,492,931 bytes; link base `0xffffff8008000000`-ish, ET_EXEC addresses shown are link-time, add `g_slide` at runtime).
- Disassembler: `aarch64-linux-android-objdump.exe` (NDK r20b)
- Symbol reader: `llvm-nm.exe`
- Source cross-check: `[WORKSPACE]\huawei_kernel_src\Code_Opensource\kernel`
  (`include/linux/cred.h`, `include/linux/capability.h`,
  `include/uapi/linux/capability.h`, `kernel/cred.c`,
  `security/selinux/hooks.c`, `arch/arm64/configs/merge_kirin990_defconfig`)

---

## 0. Verdict (short)

| Question | Answer |
|---|---|
| `task_struct.cred` | **0x9E8** ✔ matches assumption |
| `task_struct.real_cred` | **0x9E0** ✔ matches assumption |
| `uid`/`gid` | **0x04 / 0x08** ✔ |
| `euid`/`egid` | **0x14 / 0x18** ✔ |
| `fsuid`/`fsgid` | **0x1C / 0x20** ✔ |
| `security` | **0x78** ✔ matches assumption |
| `user` | **0x80** ✔ matches assumption |
| `user_ns` | **0x88** ✔ matches assumption |
| `group_info` | **0x90** ✔ matches assumption |
| `sizeof(struct cred)` | **0xA8 (168)** ✔ matches assumption |
| `CAP_SETUID` | **7** ✔ (bit 7 of `cap_effective`) |
| `CONFIG_DEBUG_CREDENTIALS` | **NOT set** (fields NOT shifted) |

**No field offset differs from the exploit's assumed layout.**
The only correction to the starting notes is item §8 (the "+0x3f8 uid load"
note is mislabeled — see there).

---

## 1. Field-offset table (device-disassembly evidence)

`cred->` offsets. Sizes: `atomic_t`/`kuid_t`/`kgid_t`/`unsigned` = 4 B;
`kernel_cap_t` = 8 B (2×u32); pointers = 8 B.

| Field | Offset | Size | Device evidence (link addr / function) |
|---|---|---|---|
| `usage` | **0x00** | 4 | `cred_alloc_blank.cfi+0x38` `str w8,[x19]` (atomic_set usage=1); `prepare_creds.cfi+0x5c` `str w8,[x19]` |
| `uid` | **0x04** | 4 | `SyS_setpriority.cfi+0x124` `ldr w8,[x25,#4]` (x25=cred); `+0x3bc` `ldr w8,[x25,#4]`; `SyS_setresuid.cfi+0xe0` `ldr w8,[x20,#4]`; `cap_task_fix_setuid.cfi+0x2c` `ldr w9,[x1,#4]` |
| `gid` | **0x08** | 4 | `SyS_setresgid.cfi+0xdc` `str w23,[x19,#8]`; `+0x108` `ldr w9,[x22,#8]` |
| `suid` | **0x0C** | 4 | `cap_task_fix_setuid.cfi+0x3c` `ldr w9,[x1,#12]`; `SyS_setresuid.cfi+0x1fc` `ldr w8,[x20,#12]` |
| `sgid` | **0x10** | 4 | `SyS_setresgid.cfi+0xf4` `str w20,[x19,#16]`; `+0x19c` `ldr w8,[x22,#16]` |
| `euid` | **0x14** | 4 | `commit_creds.cfi+0x48` `ldr w8,[x20,#20]`; `cap_task_fix_setuid.cfi+0x34` `ldr w9,[x1,#20]`; `SyS_setpriority.cfi+0x1dc` `ldr w9,[x9,#20]` |
| `egid` | **0x18** | 4 | `commit_creds.cfi+0x58` `ldr w9,[x20,#24]`; `SyS_setresgid.cfi+0xe8` `str w21,[x19,#24]` |
| `fsuid` | **0x1C** | 4 | `commit_creds.cfi+0x68` `ldr w9,[x20,#28]`; `cap_bprm_set_creds.cfi+0x290` `stp w10,w8,[x20,#28]` |
| `fsgid` | **0x20** | 4 | `commit_creds.cfi+0x78` `ldr w9,[x20,#32]`; `SyS_setresgid.cfi+0x100` `str w8,[x19,#32]` |
| `securebits` | **0x24** | 4 | `cap_task_fix_setuid.cfi+0x24` `ldr w8,[x8,#36]` (+0x90 `ldrb w8,[x8,#36]`); `cap_bprm_set_creds.cfi+0x2e8` `ldr w10,[x20,#36]` |
| `cap_inheritable` | **0x28** | 8 | `cap_bprm_set_creds.cfi+0x40` `ldp x9,x10,[x21,#40]` (x9=+0x28); `+0xc0` `ldr x10,[x21,#40]` |
| `cap_permitted` | **0x30** | 8 | `commit_creds.cfi+0xd0` `ldr x8,[x19,#48]` / `ldr x9,[x20,#48]`; `cap_task_fix_setuid.cfi+0x60` `stp xzr,xzr,[x0,#48]` clears 0x30+0x38; `cap_bprm_set_creds.cfi+0x2e8` `str x8,[x20,#48]` |
| `cap_effective` | **0x38** | 8 | `cap_capable.cfi+0x60` `add x8,x20,#(cap>>5)*4` then **`ldr w8,[x8,#56]`** (bit test = `cap_effective[cap>>5]`); `cap_task_fix_setuid.cfi+0xdc` `ldr x9,[x0,#56]` / `str x9,[x0,#56]`; `cap_bprm_set_creds.cfi+0x2f0` `str x12,[x20,#56]` |
| `cap_bset` | **0x40** | 8 | `cap_bprm_set_creds.cfi+0xd4` `ldr x9,[x21,#64]` |
| `cap_ambient` | **0x48** | 8 | `cap_bprm_set_creds.cfi+0x38` `ldr x8,[x21,#72]` / `+0xcac` `str xzr,[x20,#72]`; `cap_task_fix_setuid.cfi+0x64` `str xzr,[x0,#72]` |
| `jit_keyring` | **0x50** | 1 | (CONFIG_KEYS layout — byte, padded to 0x58) |
| `session_keyring` | **0x58** | 8 | `prepare_creds.cfi+0x94` `ldr x8,[x19,#88]` → `key_get` |
| `process_keyring` | **0x60** | 8 | `prepare_creds.cfi+0x100` `ldr x8,[x19,#96]` → `key_get` |
| `thread_keyring` | **0x68** | 8 | `prepare_creds.cfi+0x1a8` `ldr x8,[x19,#104]` → `key_get` |
| `request_key_auth` | **0x70** | 8 | `prepare_creds.cfi+0x22c` `ldr x8,[x19,#112]` → `key_get` |
| `security` | **0x78** | 8 | `selinux_cred_prepare.cfi+0xc` `ldr x20,[x1,#120]`; `+0x44` `str x8,[x19,#120]`; `selinux_cred_alloc_blank.cfi+0x54` `str x8,[x19,#120]`; `prepare_creds.cfi+0x2b8` `str xzr,[x19,#120]` (NULL before LSM prepare) |
| `user` | **0x80** | 8 | `SyS_setpriority.cfi+0x11c` `ldr x0,[x25,#128]`; `prepare_creds.cfi+0x80` `ldr x8,[x19,#128]` → `get_uid`; `commit_creds.cfi+0x248` `ldr x8,[x19,#128]` |
| `user_ns` | **0x88** | 8 | `commit_creds.cfi+0xa8` `ldr x9,[x20,#136]`/`ldr x11,[x19,#136]` (then walks `ns->parent`); `cap_capable.cfi+0x24` `ldr x8,[x20,#136]`; `SyS_setpriority.cfi+0x20c` `ldr x21,[x8,#136]` |
| `group_info` | **0x90** | 8 | `prepare_creds.cfi+0x90` `ldr x8,[x19,#144]` → `get_group_info`; `cap_capable.cfi+0x100` `ldr x9,[x9,#144]` (then `ngroups`@+4, `gid[]`@+8) |
| `rcu` (union w/ `non_rcu`) | **0x98** | 16 | `put_cred_rcu`/`abort_creds` path `add x0,<cred>,#0x98` then `__call_rcu` (`cred_alloc_blank.cfi+0x120`, `commit_creds.cfi+0x310`, `prepare_creds.cfi+0x3b0`, `exit_creds.cfi+0x60`) |
| **`sizeof(struct cred)`** | **0xA8** | 168 | `rcu` ends at 0x98+0x10 = **0xA8**; also `cred_init` passes 0xa8 to `kmem_cache_create`, `prepare_creds` memcpy's 0xa8 |

### `task_struct` anchors
| Field | Offset | Evidence |
|---|---|---|
| `real_cred` | **0x9E0** | `commit_creds.cfi+0x270` `add x8,x21,#0x9e0` / `stlr x19,[x8]`; `get_task_cred.cfi+0x1c` `ldr x20,[x0,#2528]` |
| `cred` | **0x9E8** | `SyS_setpriority.cfi+0x3c` `ldr x25,[x19,#2536]`; `commit_creds.cfi+0x27c` `add x9,x21,#0x9e8` / `stlr x19,[x9]`; `override_creds.cfi+0x4` `add x9,x8,#0x9e8` |

Function roots used (n-symbol → `.cfi` body trampolines verified):
`cap_capable.cfi`=0xffffff800877fc20, `cap_task_fix_setuid.cfi`=0xffffff8008781200,
`cap_bprm_set_creds.cfi`=0xffffff8008780a4c, `commit_creds.cfi`=0xffffff80081aa884,
`prepare_creds.cfi`=0xffffff80081aa3e4, `cred_alloc_blank.cfi`=0xffffff80081aaf50,
`selinux_cred_prepare.cfi`=0xffffff8008793850,
`selinux_cred_alloc_blank.cfi`=0xffffff80087937ac,
`cred_init.cfi`=0xffffff800a8b0940, `SyS_setpriority.cfi`=0xffffff800818e354,
`SyS_setresuid.cfi`=0xffffff800818fd1c, `SyS_setresgid.cfi`=0xffffff80081901bc.

---

## 2. `CAP_SETUID` = 7

`include/uapi/linux/capability.h`:
```
152: #define CAP_SETGID           6
157: #define CAP_SETUID           7
```

`kernel_cap_t` is 2× u32 (so bits 0–31 live in word 0):
```
include/linux/capability.h:20   #define _KERNEL_CAPABILITY_U32S   _LINUX_CAPABILITY_U32S_3
include/linux/capability.h:24   typedef struct kernel_cap_struct { __u32 cap[_KERNEL_CAPABILITY_U32S]; } kernel_cap_t;
include/uapi/linux/capability.h:37  #define _LINUX_CAPABILITY_U32S_3 2
```
Therefore **bit 7 of `cred->cap_effective` (word 0, offset 0x38) is `CAP_SETUID`**.
The same LSB indexing is confirmed on-device by `cap_capable`: it computes
`word = cap >> 5`, `bit = 1 << (cap & 31)` and tests `cred->cap_effective[word]`
at 0x38. `CAP_SETUID`=7 ⇒ word 0, bit 7 ⇒ test mask `0x80` against the u32 at
`cred+0x38`.

---

## 3. `sizeof(struct cred)` and the actual allocation

**`sizeof(struct cred) = 0xA8 = 168 bytes`.** Two independent on-device proofs:

```
cred_init.cfi @ 0xffffff800a8b0940:
  +0x00 stp  x29, x30, [sp,#-16]!
  +0x08 adrp x0, 0xffffff800a45c000            ; "cred_jar" string
  +0x0c mov  w3, #0x2000                       ; SLAB_HWCACHE_ALIGN
  +0x10 add  x0, x0, #0xa2b                    ; -> 0xffffff800a45ca2b = "cred_jar"
  +0x14 mov  w1, #0xa8                         ; <== sizeof(struct cred) = 168
  +0x18 movk w3, #0x404, lsl #16               ; SLAB_PANIC (0x40000)|SLAB_ACCOUNT (0x4000000)
  +0x1c mov  x2, xzr
  +0x20 mov  x4, xzr
  +0x24 bl   kmem_cache_create.cfi
  +0x28 adrp x8, 0xffffff800b287000
  +0x2c str  x0, [x8,#2392]                    ; cred_jar = 0xffffff800b287958
```
Cross-check, source `kernel/cred.c:587`:
`cred_jar = kmem_cache_create("cred_jar", sizeof(struct cred), 0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);`

```
prepare_creds.cfi @ 0xffffff80081aa3e4:
  +0x24 ldr  x0, [x8,#2392]                    ; cred_jar
  +0x38 bl   __memcpy  with w2 = #0xa8          ; memcpy(new, old, sizeof(struct cred))
```
`cred_alloc_blank` also allocates from `cred_jar` (`ldr x0,[x8,#2392]`,
`kmem_cache_alloc.cfi`), then writes `usage`@0x00, `security`@0x78 and the
RCU head at 0x98.

`cred_jar` symbol: `llvm-nm` reports `ffffff800b287958 b cred_jar` (BSS
pointer); `cred_init` stores the cache pointer there (`0xb287000 + 2392`).

**Grooming note (does not change any field offset):** the cache is created with
`SLAB_HWCACHE_ALIGN`, so on arm64 the per-object stride is rounded up to the
64-byte cache line: `ALIGN(0xA8, 0x40) = 0xC0 (192)`. The requested object size
— and therefore `sizeof(struct cred)` — is **0xA8**; the slab slot stride is
0xC0. Use 0xA8 for "how many bytes a cred occupies" and 0xC0 for heap-slot
arithmetic.

---

## 4. `CONFIG_DEBUG_CREDENTIALS`: **not set** (fields are NOT shifted)

Config citation — the only Kirin-990 config shipped in the source drop
(`arch/arm64/configs/merge_kirin990_defconfig`):
```
6117: # CONFIG_DEBUG_CREDENTIALS is not set
 231: CONFIG_MULTIUSER=y
6224: CONFIG_KEYS=y
6235: CONFIG_SECURITY=y
6247: CONFIG_SECURITY_SELINUX=y
```
(No `CONFIG_DEBUG_CREDENTIALS=y` / no `RANDSTRUCT` / `CONFIG_GCC_PLUGINS is not set`.)

This is **independently proven from the device image itself**, not just the
config file — if `DEBUG_CREDENTIALS` were on, `subscribers`/`put_addr`/`magic`
would insert 16 bytes and everything would move +0x10:
1. `cred_init` creates the cache with size **0xA8** (would be 0xB8 with the debug fields).
2. `prepare_creds` copies **0xA8** bytes (would be 0xB8).
3. `security` is at **0x78** (would be 0x88), confirmed by SELinux LSM code.
4. `cred_alloc_blank` writes only `usage` at 0x00 — it does **not** write a
   `magic` field (the `new->magic = CRED_MAGIC` block is compiled out).

⇒ The offsets in §1 are the live ones. (Same conclusion independently from the
source `#ifdef CONFIG_DEBUG_CREDENTIALS` guards in `include/linux/cred.h:113`
and `kernel/cred.c`.)

Layout dependency cross-check: `CONFIG_KEYS=y` adds `jit_keyring` + 4 key
pointers (0x50–0x77), and `CONFIG_SECURITY=y` adds `security` (0x78) — both
present and confirmed by the key-`get` sequence in `prepare_creds`
(0x58/0x60/0x68/0x70) and by SELinux writing 0x78. `CONFIG_MULTIUSER=y` is why
`groups`/`user` fields are real pointers. No `__randomize_layout` on `struct
cred` in the shipped `include/linux/cred.h` (and compiler randstruct plugin is
off), so the order is deterministic.

---

## 5. Exploit-relevant bitmap

`cred->cap_effective` is a `kernel_cap_t` = `u32 cap[2]` at **cred+0x38**:
- word 0 (`cred+0x38`) = caps 0–31 → contains `CAP_SETUID`(7), `CAP_SETGID`(6), `CAP_SYS_ADMIN`(21)
- word 1 (`cred+0x3C`) = caps 32–63

To grant `CAP_SETUID` you set bit 7 of the u32 at `cred+0x38` (value `0x80`).
To grant the whole word: write `0xFFFFFFFF` at `cred+0x38` and `0xFFFFFFFF` at
`cred+0x3C` (also mirror into `cap_permitted` at `cred+0x30` if code paths check
permitted/effective consistency, e.g. `cap_capable` and the `cap_task_fix_setuid`
logic both consult effective).

---

## 6. Cross-check against source `struct cred` (include/linux/cred.h)

The shipped header matches the image exactly (no extra/Huawei fields, no
`__randomize_layout`):
```
atomic_t usage;                 // 0x00
kuid_t uid;                     // 0x04
kgid_t gid;                     // 0x08
kuid_t suid;                    // 0x0C
kgid_t sgid;                    // 0x10
kuid_t euid;                    // 0x14
kgid_t egid;                    // 0x18
kuid_t fsuid;                   // 0x1C
kgid_t fsgid;                   // 0x20
unsigned securebits;            // 0x24
kernel_cap_t cap_inheritable;   // 0x28
kernel_cap_t cap_permitted;     // 0x30
kernel_cap_t cap_effective;     // 0x38
kernel_cap_t cap_bset;          // 0x40
kernel_cap_t cap_ambient;       // 0x48
#ifdef CONFIG_KEYS              // CONFIG_KEYS=y
unsigned char jit_keyring;      // 0x50 (+7 pad)
struct key *session_keyring;    // 0x58
struct key *process_keyring;    // 0x60
struct key *thread_keyring;     // 0x68
struct key *request_key_auth;   // 0x70
#endif
#ifdef CONFIG_SECURITY          // CONFIG_SECURITY=y
void *security;                 // 0x78
#endif
struct user_struct *user;       // 0x80
struct user_namespace *user_ns; // 0x88
struct group_info *group_info;  // 0x90
struct rcu_head rcu;            // 0x98..0xA7
```
Huawei's only additions are in the *functions* (`hkip_check_uid_root`,
`hkip_check_xid_root`, `hkip_update_xid_root`), not in the struct.

---

## 7. Reproduction commands (host, read-only)

```powershell
$od  = "[WORKSPACE]\android-ndk-r20b\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android-objdump.exe"
$nm  = "[WORKSPACE]\android-ndk-r20b\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-nm.exe"
$img = "[FIRMWARE]\MRX-W09\extracted\vmlinux.elf"

& $nm -n $img | findstr /I "cap_capable commit_creds prepare_creds cred_alloc_blank selinux_cred cred_init cred_jar"

# cap_effective @ cred+0x38
& $od -d --start-address=0xffffff800877fc20 --stop-address=0xffffff800877fd00 $img
# cap_* + securebits
& $od -d --start-address=0xffffff8008781200 --stop-address=0xffffff8008781320 $img
# security @ 0x78
& $od -d --start-address=0xffffff8008793850 --stop-address=0xffffff80087938a8 $img
# user@0x80, user_ns@0x88, group_info@0x90, security@0x78, sizeof via memcpy 0xa8
& $od -d --start-address=0xffffff80081aa3e4 --stop-address=0xffffff80081aa4a0 $img
# sizeof(cred)=0xa8 passed to kmem_cache_create("cred_jar",...)
& $od -d --start-address=0xffffff800a8b0940 --stop-address=0xffffff800a8b0978 $img
# task real_cred@0x9E0 / cred@0x9E8
& $od -d --start-address=0xffffff80081aaaf4 --stop-address=0xffffff80081aab08 $img
```

---

## 8. Divergences / corrections to the starting assumptions

Flagging the one wrong premise and the one imprecision:

1. **The assumed cred layout is correct.** `security@0x78`, `user@0x80`,
   `user_ns@0x88`, `group_info@0x90`, `sizeof=0xA8`, `cred@0x9E8`,
   `real_cred@0x9E0`, `uid@0x04`, `euid@0x14`, `fsuid@0x1C` all match the
   device image. **No offset needs changing.**

2. **Mislabelled uid load in the starting notes.** The brief said
   `SyS_setpriority.cfi` does `ldr w8,[x25,#4]` (cred->uid) "around +0x3f8".
   In the actual image `+0x3f8` (`0xffffff800818e74c`) is
   `ldr x8,[x8,#8]` (an unrelated task/accounting load, `x8` is not the cred).
   The real `cred->uid` loads in `SyS_setpriority.cfi` are at:
   - `+0x124` (`0xffffff800818e478`) `ldr w8,[x25,#4]`
   - `+0x288` (`0xffffff800818e5dc`) `ldr w22,[x25,#4]`
   - `+0x3bc` (`0xffffff800818e710`) `ldr w8,[x25,#4]`

   The `+0x34 mrs x19, sp_el0`, `+0x3c ldr x25,[x19,#2536]` and
   `+0x11c ldr x0,[x25,#128]` anchors in the notes are all correct. Net effect:
   **the exploit's `cred->uid @0x04` and `cred->user @0x80` assumptions remain
   valid**; only the annotation offset was off.

3. **Newly pinned offsets not in the original assumption list** (were listed as
   "confirm"): all standard — `cap_inheritable 0x28`, `cap_permitted 0x30`,
   `cap_effective 0x38`, `cap_bset 0x40`, `cap_ambient 0x48`, `jit_keyring 0x50`,
   key pointers 0x58–0x70. `cap_permitted` and `cap_effective` are adjacent
   8-byte fields at 0x30/0x38, so a single 16-byte write at 0x30 sets both.

4. **`size` vs `stride` caveat:** `kmem_cache_create` is called with size
   `0xA8`, but `SLAB_HWCACHE_ALIGN` makes the slab slot stride `0xC0` on a
   64-byte-line arm64 build. This affects grooming/adjacency, **not** any field
   offset.
