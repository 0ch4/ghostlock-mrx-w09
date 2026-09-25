# COMPLETE ROOT 実装計画（permissive_map パッチ）

最終更新: 2026-09-26  対象: MRX-W09 (Kirin 990 / EMUI 11 / Linux 4.14.116)

## 目標
`--simple` で得ている **uid 0 + shell ドメイン** の root を壊さずに、
**SELinux の全クラス拒否を解除**し、さらに **cap_effective** を与えて
`mount` / `/dev/block` / 全域 DAC root（`/data/system`, `/data/misc/keystore` 等）を可能にする。

## なぜ `permissive_map` か（解析済み）
`avc_denied()` は **ソース側 type が permissive** なら拒否を許可に反転する
（`security/selinux/avc.c:1007-1012`、`services.c:1119`、本ビルドは `selinux_enforcing` が定数 1）。
つまり **shell(type 1153) を permissive にすれば全クラス一括で解除**。
- `allow_unknown` は無効（`context_struct_compute_av()` は読まない）
- `ss_initialized=0` は HKIP の write-rare 保護領域で fault
- avtab 直接書き換えは範囲が狭い

## 必要な書き込み（すべて既存の primitive）
| # | 対象 | 値 | 意味 |
|---|---|---|---|
| 1 | `policydb + 0x1C8` | `V`（カーネルポインタ、`low32(V) >= 1153`） | `permissive_map.highbit` |
| 2 | `policydb + 0x1C0` | `A`（`ebitmap_node` の実アドレス） | `permissive_map.node` |
| 3 | `cred + 0x38` | `V2`（`low32` に `CAP_SYS_ADMIN`(21)/`CAP_DAC_OVERRIDE`(1)/`CAP_SETUID`(7) 等のビット） | `cap_effective`（上位32cap は自動で全部立つ） |

`policydb` = `LINK_POLICYDB + g_slide`（既知）。`cred` は既存のリーク（`SyS_setpriority.cfi` x25）で取得済み。

## `ebitmap_node` の要件（`ss/ebitmap.h`）
```c
struct ebitmap_node { struct ebitmap_node *next; unsigned long maps[6]; unsigned long startbit; };
// EBITMAP_SIZE = 64*6 = 384, MAPSIZE = 64
```
`ebitmap_get_bit(e,1153)` は `highbit >= 1153` かつ
`startbit <= 1153 < startbit+384` かつ `maps[(1153-startbit)/64] >> ((1153-startbit)%64) & 1` を要求。
⇒ **`startbit = 1152`（384*3）で `maps[0]` の bit1 が立っているノード**が理想。

## A 案（第一候補）: 実在の属性 ebitmap ノードを使う
shell(1153) は次の属性に所属（`device_plat_sepolicy.cil`）:
`domain`(:786) `mlstrustedsubject`(:850) `appdomain`(:854) `netdomain`(:858) `coredomain`(:866)
`halclientdomain`(:948) **`hal_atrace_client`(:963 = shell traceur_app atrace)** `base_typeattr_676`(:31133)

⇒ これら属性の ebitmap は **chunk 3（startbit=1152）に bit1 が立つ実在ノード**を持つ。
**最小の `hal_atrace_client` が第一候補**（副作用が最小）。

**ノード実アドレスの取得手順（要 read primitive）**
1. `policydb.type_val_to_struct[<attr の sid>]`（`policydb+?` の配列）を読む
2. その `type_datum` の ebitmap（`.types`）の `.node` を読む
3. `startbit==1152` のノードを選ぶ（複数あれば任意）
※ 既存の **破壊的 boot_id read** primitive（`arm_rd16`/`arm_read_raw`）で 8 バイト読みが可能。
※ 手間はかかるが、**安定・非 transient**（prmem 保護）なので **panic しない**。

## B 案（対抗）: スタンプ窓を「安定化」して偽ノードを作る
以前の失敗は **MCAST（returning）carrier の窓が一過性**だったため。**pselect6 carrier は BLOCKING**
（スレッドが syscall 内に留まる）なので、**窓を常駐させられる**。窓の内容は `g_sbuf` で任意に作れるので
`startbit=1152` / `maps[0]=2` / `next=<garbage だが未参照>` の完全な偽ノードを置ける。
- 利点: **read primitive 不要**、1 回の stamp で完結
- リスク: 窓の寿命・AVC ミス歩行の安全性は実測が必要（要: 窓を保持したまま `su -c "cat /proc/self/attr/current"` 等で AVC を発生させ panic しないか確認）

## 検証手順（oracle）
1. **permissive の確認**（破壊的でない）:
   `open("/proc/self/attr/exec", O_WRONLY)` に `write("u:r:shell:s0")` → ベースライン `EACCES`、
   成功すれば permissive。
2. **cap の確認**: `capget` で `CapEff` に bit21 等が出るか。`mount -o remount,rw /` 、
   `head -c 16 /dev/block/sdd74`、`ls /data/misc/keystore`、`cat /data/system/packages.xml`。
3. 標準 `su` パス作成（permissive 後は `/data/local/{,bin,xbin}/su` の `create` が通るはず）。
4. すべて通れば **complete root**。

## 実装順序（`--simple` を壊さない）
1. `--simple` の shield + uid ゼロ + setresuid の後、**新規モード `--full`** として 3 書きを追加
   （`--simple` は現状維持）。
2. A 案の read は別モード `--findnode` で段階実行（読み値を klog へ）。
3. 成功したら `--full` を既定の推奨経路に昇格し、README/FACTS を更新。

## 既知の注意
- `cap_capable`（commoncap）は SELinux とは独立に `cap_effective` を要求 ⇒ 書き込み #3 は必須。
- `hkip_check_uid_root()` が `cap_capable` より先に走る ⇒ **pid-0 シールドは引き続き必須**。
- AVC キャッシュは期限切れしない（`flags=0` の既存エントリが残る）⇒ **パッチは利用前に適用**、
  必要なら `avc_ss_reset` 相当が必要（`/sys/fs/selinux/` の reload は使わない）。
