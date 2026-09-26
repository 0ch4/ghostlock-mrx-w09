# カーネル解析 — dm-verity + FEC が「改変データ」を元に戻す仕組みと対処

Date: 2026-09-26.  Source: `huawei_kernel_src/.../drivers/md/{dm-verity-target.c, verity_handle_4.14.c,
dm-verity-fec.c, dm-verity-fec.h}`, 実機 config（`/proc/config.gz`）, `bl_vbmeta_system.img`.

------------------------------------------------------------------------------------------
## 0. 実測した事実（これが発端）
- perfetto.rc の inode ブロック（`sdd71@block139218`）を改変 → **フラッシュに永続**
  （再起動後も sha `1be82ca9…`）。
- しかしカーネルが **`/system/etc/init/perfetto.rc` として返すのは元データ**。
- ⇒ 「raw super を書けば verity は黙認して改変データを返す」という**以前の前提は誤り**。

## 1. 検証フロー（`dm-verity-target.c`）
`verity_verify_io()`（541-607）:
```
hash_for_block -> want_digest
hash(io data)
 ├ 一致           -> validated_blocks に set, continue
 ├ oem_verity_fec_decode(...) == 0 -> continue      ★ ここで「正しい（元）ブロック」に置換
 └ verity_handle_err(...) -> 1 なら -EIO / 0 なら io データのまま提供
```
`verity_handle_err()`（261-317）:
```
if (corrupted_errs >= DM_VERITY_MAX_CORRUPTED_ERRS(=100)) return 1;   // per-boot
corrupted_errs++;
if (mode==LOGGING) return 0;
if (mode==RESTART){ ret=oem_verity_handle_err(v); /*kernel_restart はコメントアウト*/ }
return ret;   // oem_verity_handle_err は常に 0（NVE VMODE のロジックは 4 到達で return 1 だが到達不能）
```
実機: `androidboot.veritymode=enforcing` → mode=RESTART。`androidboot.vbmeta.device=PARTUUID=`（空）
→ `name_to_dev_t`→`devt_from_partuuid("")==0`（`do_mounts.c:145-148`）→ `dm_verity_avb_error_handler`
は `fail_no_dev` で **vbmeta をスタンプしない**（遅延 brick 無し）。

## 2. なぜ元データが返るか = **FEC が黙って復元する**
`oem_verity_fec_decode()`（`verity_handle_4.14.c:444-486`）→ `verity_fec_decode()`（`dm-verity-fec.c:423-484`）:
- `verity_soft_hash`（io データを hash し比較）→ 不一致。
- `verity_fec_decode` → **RS 訂正**。成功すれば元ブロックに復元して 0 を返す。
- `fec_decode_rsb()`（365-406）は訂正後、**期待ハッシュで再検証**（391-403）。一致すれば 0。
- `verity_fec_decode` は訂正済みブロックを io バッファへコピー（475-480）→ `continue`。

### FEC の構成（`dm-verity-fec.c` / `.h`）
```
roots = fec_roots（テーブル指定, 本機 = 2）
rsn   = 255 - roots            (= 253)
blocks(fec_blocks) = data_blocks + hash_blocks + metadata
rounds = ceil(fec_blocks / rsn)
loop : 各バイト位置 k が「別々の RS(255,rsn) コード」, rsn ブロックにインターリーブ（444-451）
fec_interleave(off): mod=off%rsn; off/=rsn; return off + mod*(rounds<<block_bits)   (38-44)
fec_read_bufs(): RS グループ = { fec_interleave(rsb*rsn + i) : i=0..rsn-1 } を読む（207-303）
fec_read_parity(): position = (index+rsb)*roots; block = position>>block_bits;
                   read(fec_dev, fec_start + block)                      (66-86)
```
⇒ **1 ブロックだけ壊しても、各コードの誤りは高々1シンボル（roots/2=1）→ 全て訂正可能**
→ FEC が元ブロックを返す。**単一ブロック改変は原理的に無効**。

### 実機の system パーティション幾何（`bl_vbmeta_system.img` HASH_TREE, big-endian）
```
image_size  = 0xBFEB1000 = 3,220,209,664   -> data_blocks = 786,184
tree_offset = 0xBFEB1000 ; tree_size = 0x182F000 -> hash_blocks = 6,191
fec_offset  = 0xC16E0000 (= 3,245,867,008 ; 792,449 block)
fec_size    = 0x1878000  = 25,690,112      -> rounds = fec_size/(4096*roots=2) = 3136 ; rsn=253
data_blk = hash_blk = 4096 ; fec_num_roots = 2
（fec_offset + fec_size = 3,271,557,120 = system パーティション末尾と一致）
```
※ パーティション先頭 = super byte 2 MiB（dm-0 == sdd71+2MiB、EROFS magic 一致で実証）。
※ `fec_blocks`（=rounds から逆算 ≈ 793,408）は data+hash+metadata。厳密値は verity テーブル依存。

## 3. 対処（FEC を外して改変を効かせる）
| 案 | 手段 | 効果/コスト |
|---|---|---|
| **A** | 対象と**同じ RS グループ**の**もう1ブロック**も改変 | 同一 codeword に誤り≥2 → 全グループ訂正不能 → verity 許容(≤100) → **改変データが提供**。2ブロック書換え |
| **B** | 対象グループの **FEC パリティを破壊**（`fec_start + (index+rsb)*roots`） | FEC 訂正不能 → verity 許容 → 改変データ提供。FEC 領域は hash tree 対象外＝**verity エラーを増やさない** |

いずれも `oem_verity_fec_decode` を失敗させて `verity_handle_err`(tolerate) に落とすのが本質。

## 4. 残作業（実機で潰す）
1. `rsb`/`fec_start`/RS グループ成員の**厳密計算**（`fec_blocks` の確定＝verity テーブル/descriptor 精査）。
2. 案 A の最小検証: 対象ブロック + 同グループ1ブロックを改変 → 冷間起動 → **改変内容が返るか**確認。
3. 実現すれば `.rc` 注入（`CHANGE_08`）が**初めて成立** → 起動時 overlay による恒久 GMS の道が開く。

## 5. 副産物（重要）
- 我々の改変は FEC が静かに訂正したため **verity エラーを出していない** → **端末不安定化の原因ではない**
  （不安定化は exploit のスピン/watchdog。`STATUS_20260926.md` と整合）。
- 端末は revert 済み（`sdd71@139218 = ffec8da9…`）でクリーン。
