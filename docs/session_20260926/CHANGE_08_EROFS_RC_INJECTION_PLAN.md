# CHANGE_08 — EROFS `.rc` injection for persistent GMS (PLAN, not yet written)

Date: 2026-09-26
Goal: make the native GMS overlay re-applied **at boot by init itself**, with no exploit.

## Why this is possible (corrected premises)
1. `DM_VERITY_MAX_CORRUPTED_ERRS = 100` (Huawei changed it from 3). `corrupted_errs` is
   per-boot; on a tolerated error `verity_handle_err()` returns 0 and
   `verity_verify_io()` returns the **on-disk (modified) data** (`dm-verity-target.c:604`).
2. The feared vbmeta "AVE0" stamp does **not** happen:
   `androidboot.vbmeta.device=PARTUUID=` is empty -> `devt_from_partuuid("")` returns 0
   (`do_mounts.c:145-148`) -> `name_to_dev_t` fails -> `dm_verity_avb_error_handler` goes to
   `fail_no_dev` and never calls `invalidate_vbmeta`.  No delayed brick.
3. `/system` is EROFS (LZ4, legacy).  Most `/system/etc/init/*.rc` are **FLAT_INLINE**
   (uncompressed inline data) -> editable by overwriting bytes in the inode's metadata block.

## Target
`/system/etc/init/perfetto.rc` (tracing; safe to lose)
- nid = 17754368, inode at byte 568139776 (block-aligned, block-offset 0)
- datamode = 2 (FLAT_INLINE), xattr_icount=2 (xattrsize 16), size = 2323
- inline data at byte 568139824 (+48), 2323 bytes, ends at 568142147 (< block end 568143872)
- Replace content within the **same 2323 bytes** (i_size unchanged) -> only ONE 4096-byte
  verity block differs.  (`perfetto.rc`'s tracing rules are dropped.)

## Payload (403 bytes; padded with '#' to 2323)
```
# ---- persistent GMS overlay (injected) ----
on post-fs-data
    setprop gl.boot.injected 1
    mount overlay overlay /system/etc/permissions ro lowerdir=/data/gls/perm:/system/etc/permissions
    mount overlay overlay /system/etc/sysconfig ro lowerdir=/data/gls/sys:/system/etc/sysconfig
    mount overlay overlay /system/priv-app ro lowerdir=/data/gls/priv:/system/priv-app
# ---- end injected ----
```

## Persistent data (/data, survives reboots)
Copy the GMS additions (already in `/data/local/tmp/gms_stage`, 135 MB) to:
```
/data/gls/perm  <- gms_stage/permissions   (3 privapp-permissions XMLs)
/data/gls/sys   <- gms_stage/sysconfig     (4 sysconfig XMLs)
/data/gls/priv  <- gms_stage/priv-app      (GoogleServicesFramework/ Phonesky/ PrebuiltGmsCore/)
chcon -R u:object_r:system_file:s0 /data/gls
```

## Write (physical super = dm-0 == sdd71 + 2MiB, verified EROFS magic)
- block: byte 570236928 = sector/block **139218** (bs=4096), 1 block
- write:   `dd if=perfetto_block_new.bin of=/dev/block/sdd71 bs=4096 seek=139218 count=1 conv=notrunc`
- rollback:`dd if=perfetto_block_orig.bin of=/dev/block/sdd71 bs=4096 seek=139218 count=1 conv=notrunc`
- orig/new blocks + `inject_plan.json` saved in `evidence/erofs/`
- orig_sha256(block)=ffec8da9…  new_sha256(block)=795afc14…

## Verification (after cold boot)
1. `getprop gl.boot.injected` == 1            -> injection + init parse worked
2. `mount | grep -E 'overlay .*/system'`      -> boot overlays present
3. `dumpsys package com.google.android.gms | grep privateFlags` -> PRIVILEGED (no exploit run)
4. 15-min stability watch (watchdog)

## Risk
- 1 verity block mismatch, tolerated (<=100); FEC cannot correct 2287 changed bytes.
- No vbmeta stamp (proved above).
- Failure mode if offset wrong: corruption of an EROFS metadata block -> possible boot
  failure.  Mitigated by: exact inode/block math, original block saved, single-block scope.
