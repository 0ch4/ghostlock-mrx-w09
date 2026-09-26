# Bootloader / secure-boot static analysis — MRX-W09 (Kirin 990, EMUI 11)

Date: 2026-09-26
Method: **read-only** dump of boot-chain partitions as root (`/data/local/tmp/su -c dd`),
pulled to host, analysed offline. **No partition was written.**

Partitions dumped (device by-name → block):
| name | block | size |
|---|---|---|
| fastboot (LK) | sdd33 | 12 MB |
| bl2 | sdd16 | 4 MB |
| hhee | sdd31 | 4 MB |
| trustfirmware | sdd58 | 2 MB |
| security_dtb | sdd56 | 2 MB |
| vbmeta | sdd65 | 4 MB |
| vbmeta_system | sdd49 | 1 MB |
| veritykey | sdd12 | 1 MB |
| certification | sdd5 | 1 MB |
| oeminfo | sdd6 | 96 MB |
| nvme | sdd4 | 5 MB |
| vrl | sdd1 | 512 KB |

## 1. Encrypted / unreadable (the actual BL code) — entropy 256/256, no known strings
- `fastboot` (LK) — `ANDROID!`/`fastboot`/`unlock` all absent
- `bl2`
- `hhee`
- `trustfirmware`
- `security_dtb`

=> The bootloader implementation **cannot be reverse-engineered** from flash. Kirin 990
encrypts xloader/fastboot (consistent with public reporting).

## 2. Cleartext structures

### vbmeta (top-level, sdd65) — AVB0, big-endian (libavb standard)
```
release = "avbtool 1.1.0"
algorithm = SHA256_RSA2048 (1)
authBlk=0x140  auxBlk=0x2200  rollbackIndex=0  flags=0
13 x CHAIN_PARTITION:
  boot, ramdisk, vbmeta_system, vbmeta_vendor, vbmeta_odm,
  eng_vendor, eng_system, version, vbmeta_hw_product,
  preload, preas, preavs, vbmeta_cust
```
Verification root = RSA-2048 public key (private key = Huawei's, not available).
=> forging a signed image is impossible without the private key.

### vbmeta_system (sdd49) — AVB0
```
1 x HASH_TREE for "system":
  dm_verity_version=1, data_block=4096, hash_block=4096, fec_num_roots=2,
  hash_algorithm="sha1", image_size~0xBFEB1000, tree/fec offsets present
+ PROPERTY descriptors
```
=> dm-verity over `system` confirmed. (Runtime corruption tolerance is the known
3-block window; see PERSISTENCE_RAW_SUPER doc.)

### nvme (sdd4) — cleartext lock flags, each with a 4-byte integrity value
```
FBLOCK  @0x29c04  type=1 len=1  chk=a26c4938  data=01
ADBLOCK @0x29b84  type=1 len=1  chk=ffe2de45  data=00
DEVLOCK @0x27204  type=1 len=8  chk=b5a674b0  data=11 11 00 00 4c 4c 4c 4c
WVLOCK  @0x26804  type=1 len=0x44 chk=1514df00 data=55...
MACFBW  @0x22784  type=1 len=4  chk=aa057fdf
ATSTATE @0x29604  type=1 len=1  chk=dd19a493
```
=> Flags are plaintext but **tamper-evident** (per-entry checksum). Generation method is
inside the encrypted BL => cannot recompute after editing.

### Others
- `oeminfo` unlock-code area @0xA00 = all zeros => **locked**.
- `vrl` (anti-rollback rollback-lock) = all zeros.
- `veritykey` = all zeros (unused on this build).
- `certification` = structured/encrypted blob (not readable).

## 3. Verdict
1. **BL code is encrypted** => no static reverse-engineering / bypass hunting.
2. **AVB RSA-2048 + dm-verity** => cannot forge boot/system images (no private key).
3. **Lock flags are integrity-tagged** and EMUI10+ unlock needs an RDLOCK RSA signature.
4. Non-chained partitions (`kpatch`, `patch`, `modem_fw`, firmware blobs) are verified by
   the (encrypted) BL / TEE / fuses — not actionable at runtime.

=> **Bootloader unlock and any BL-based persistence are closed.** This static dig yields no
bypass, and confirms the per-boot overlay design as the only viable GMS route.

## Appendix — evidence files (host, not pushed)
`session_20260926_stabilize_oneshot/evidence/bootloader/`
```
fb_lk.img bl2.img hhee.img trustfirmware.img security_dtb.img
vbmeta.img vbmeta_system.img veritykey.img certification.img
oeminfo.img nvme.img vrl.img
bl_*.img (same, convenience copies)
scripts/read_bl_static.sh , scripts/parse_vbmeta.ps1
```
