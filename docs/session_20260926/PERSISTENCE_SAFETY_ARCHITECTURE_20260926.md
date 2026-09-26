# PERSISTENCE SAFETY ARCHITECTURE — MRX-W09 (2026-09-26)

目的: 「native GMS の永続化」を、**二度目の factory reset でも永久文鎮にならない**ことを
**設計要件として組み込んで**再設計する。あわせて**現在の危険 payload（`perfetto.rc` 注入）を
marker へ無害化**する第一変更を定義する。

対象: MRX-W09 / 11.0.0.235(C635E3R1P6) / serial QBK6R20611000374。
前提知識: `POSTMORTEM_BRICK_20260926.md`, `FEC_ANALYSIS_20260926.md`, `PERSISTENCE_RAW_SUPER_20260926.md`,
`ROOTSHELL_MEMO_20260926.md`, `STATUS_20260926.md`, および公開 repo の gms 設計文書群。

---

## 0. 結論（先に要点）

1. **起動時の init ドメインコード実行（注入 `.rc`）は既に手に入っている**。足りないのは中身だけ。
2. 危険なのは「mount」ではなく **「誤ラベルのまま mount が"成功"すること」**。
   現在の payload は staging 不在で mount が**失敗**するため無害（factory reset が自動 disarm した）。
3. **永久文鎮を防ぐ唯一の実効的 fail-safe は `/data` ゲート**である。
   （eRecovery は flash 不可＝実測。書き込みで戻すにも root/exploit が要る。⇒ reset が最終手段。）
4. したがって設計上の憲法は **「危険な層・ゲートは `/data` のみ。不在なら必ず失敗する」**（§3 SI-1）。
5. 第一変更は **`perfetto_block_marker.bin` を書いて無害化**（§5）。boot時 chcon も mount も無い。

---

## 1. 本セッションで更新された確定事実（実機）

| # | 事実 | 証拠 |
|---|---|---|
| 1 | 通常起動・adb 可（`uid=2000 shell`, `u:r:shell:s0`）。build 235、`verifiedbootstate=green`, `flash.locked=1` | `adb shell id/getprop` |
| 2 | **注入 `.rc` は毎ブート実行されている**（`setprop gl.boot.injected 2`） | `getprop` = 2、`cat /system/etc/init/perfetto.rc` |
| 3 | **FEC ゼロ化は有効**（改変ブロックが実際に読まれる） | `cat` が注入内容を返す |
| 4 | **fail-safe の実証**: factory reset は `/system` を触らない → `.rc` 残存、staging 不在で mount 失敗 → 起動可 | 本セッション |
| 5 | `/data/local/tmp` は空（reset でツール全消失） | `ls` |
| 6 | `/data` = **f2fs FBE**（`inline_encrypt,sdp_encrypt`）。overlay upper を /data に置くと **EINVAL 実績** | `mount` |
| 7 | **`/cache` = ext4・非暗号・rw**（97M 中 89M free, nosuid）→ overlay 可だが**容量不足** | `df/mount` |
| 8 | `/preas`, `/vendor/preavs` = **erofs ro** → 「preas に system app」案は**死** | `mount` |
| 9 | **ROM 自身が lower-only ro overlay を使う**（`/system/product/priv-app overlay ro lowerdir=/preas/priv-app:/system/product/priv-app`） | `mount` |
| 10 | init builtins（実在）: `chown chmod mkdir write restorecon(_recursive) setprop mount trigger start stop exec export …`（`chcon` は未確認。`/system/bin/init` は shell から読めない） | `grep /system/etc/init/*.rc` |
| 11 | 起動時 exec はほぼ全て init→専用ドメインへ typetransition（init に残るものは稀） | 既存解析 |
| 12 | uptime 9分で **loadavg 28** = watchdog リセット素地 | `uptime` |

---

## 2. 「永久文鎮」ベクターと対策（A）

| # | ベクター | 永久化する理由 | 対策 |
|---|---|---|---|
| **PB1** | overlay の層を **factory reset で消えない場所**に置く（/cache, /metadata, /splash2, /mnt/hisee_fs, /preas, /system） | reset しても不正ラベル層が残り mount が成功し続ける → 逃げ道消滅 | **層は `/data` のみ**。他をゲートに使わない |
| **PB2** | 無条件 mount（/data 非依存。例 tmpfs upper のみ） | reset で無効化できない | **全 mount の lowerdir に `/data` 配下を含ける**（不在→失敗） |
| **PB3** | boot 時に **chcon してから mount** | chcon 失敗→誤ラベルのまま mount 成功→brick | **boot 時 chcon を禁止**。「staging 在⇒ラベル正」を staging 時に確定 |
| **PB4** | 復旧モード（charger/emergency/eRecovery）でも走り、復旧に必要なパスを壊す | 逃げ道まで消える | mount 先は**3ディレクトリ限定**＋**通常起動限定トリガ**。今回 Emergency backup mode は生存（実測） |
| **PB5** | EROFS メタデータ / FEC / verity 構造の破壊 | 再 flash 以外不可 | **単一 4096B ブロック・同サイズのみ**。stock 常備。metadata/verity/FEC を触らない |
| **PB6** | 復旧手段の欠如（eRecovery は flash 不可＝実測） | reset が唯一の逃げ道 | **fail-safe を `/data` ゲートに一本化** = reset が常に disarm |

> 補足: HiSuiteProxy のシステムリカバリは `rescue_recovery_boot` で
> `partition length get error` / `Command not allowed` となり**flash 不能**（実測）。
> ⇒ 「壊したら再 flash」は当てにできない。**設計で fail-safe を保証する**のが必須。

---

## 3. 安全不変条件（B）— 設計の憲法

- **SI-1（/data ゲート）**: 危険操作はすべて **`/data` の中身の存在に依存**し、不在なら **失敗**する。
  （⇒ factory reset が常に disarm する。）
- **SI-2（ラベルは staging 時に確定）**: **「staging が存在する ⇒ ラベルは正しい」**を成立させる。
  boot 時は検証もしない・chcon もしない（誤ラベル成功の余地をゼロにする）。
- **SI-3（通常起動限定）**: boot hook は通常起動でのみ発火。charger/emergency/recovery に影響しない。
- **SI-4（最小改変）**: 変更は単一ブロック・同サイズ。`perfetto_block_orig.bin` を常備し読み戻し比較。
- **SI-5（disarm 試験）**: 各変更後に **「staging を消して再起動 → 正常起動」を必ず実施**（reset シナリオの再現）。

---

## 4. 安全設計（C）— 最終形の骨格

```
[一度だけ・root 窓 (permissive)]
  /data/gls/perm/*.xml            ← chcon system_file, chown 0:0, chmod a+rX
  /data/gls/sys/*.xml
  /data/gls/priv/{PrebuiltGmsCore,GoogleServicesFramework,Phonesky}/*.apk
  ※ /data のみ（reset で消える）。boot 時 chcon はしない（SI-2）。

[/system/etc/init/perfetto.rc（注入・単一ブロック・stock 退避あり）]
  on post-fs-data                                  # 通常起動のみ（SI-3）
      setprop gl.boot.hook 1
      mount overlay overlay /system/etc/permissions ro lowerdir=/data/gls/perm:/system/etc/permissions
      mount overlay overlay /system/etc/sysconfig   ro lowerdir=/data/gls/sys:/system/etc/sysconfig
      mount overlay overlay /system/priv-app        ro lowerdir=/data/gls/priv:/system/priv-app
      # upper/work 無し（ROM と同じ lower-only ro）。boot 時 chcon 無し。

[fail-safe] /data/gls 不在 → 3 mount が ENOENT で失敗 → overlay 無し → 通常起動
           = factory reset が自動 disarm（SI-1）。
```

残る決定点（§6）: **init が `/data` を `restorecon(_recursive)` するか**。
するなら boot 時ラベルが失われ SI-2 が崩れる（→ 代替設計が必要）。しない可能性が高い
（Huawei rc は特定サブディレクトリのみ restorecon している）。

---

## 5. 無害化（D）— marker 書き込み（第一変更）

### 5.1 素材（`evidence/erofs/`, すべて 4096B）

| ブロック | sha256 | 役割 |
|---|---|---|
| `perfetto_block_orig.bin` | `ffec8da918d01eacfed083464944b75ee3d3811054d1982e6d0ccbef195e7441` | **stock**（完全 revert 用） |
| `perfetto_block_new.bin` | `795afc14af9487330650b5372D21B5AB6E0F93C76A1FD87827558144C36BAE9E` | 中間世代（/data/gls パス版） |
| `perfetto_block_full.bin` | `f4c56fbcbc9357c1d659fef1e00220dc3810deb8c333245c9b6f26589d807675` | **現在の on-disk（危険 payload）** |
| `perfetto_block_marker.bin` | `1be82ca9fba253332ac00e2ee61bbbea061028b440647f8c19f6d03f990238fe` | **marker のみ（起動確認済み）** ← 無害化に使用 |

`inject_plan_marker.json` / `inject_plan_full.json`:
- `inode_off=568139776`, `inline_off=568139824`, `size=2323`, `block_index=138706`,
  `super_seek_4096 = 139218`（= super_phys_block 570236928 / 4096）, `verity_blocks_changed=1`。

### 5.2 無害化後の中身（marker）
`mount` 3 行を削除し `setprop gl.boot.injected 1` のみ（payload_len=100）。
boot 時 chcon も mount も無いので **SI-1/SI-2 を自動的に満たす**（誤ラベル mount の余地ゼロ）。

### 5.3 手順（exploit で root を取り、reboot を挟まずに実行）
```
# 0) ツール再投入（/data/local/tmp は空。gms_stage は絶対に作らない）
#    ghostlock_e / inject_hook / shellcode.bin / perfetto_block_marker.bin
# 1) enabler で perf=-1（place/hook → bugreportz 1回）
# 2) root 取得（shield-free --root）→ /data/local/tmp/su
# 3) 現状確認（strip 前の証拠）: dd if=/dev/block/sdd71 bs=4096 skip=139218 count=1
#    → sha256 == f4c56fbc… を確認
# 4) 書き込み:
#    su -c 'dd if=/data/local/tmp/perfetto_block_marker.bin of=/dev/block/sdd71 \
#              bs=4096 seek=139218 count=1 conv=notrunc'
# 5) 読み戻し: dd if=/dev/block/sdd71 bs=4096 skip=139218 count=1 → sha256 == 1be82ca9…
# 6) 再起動 → gl.boot.injected = 1 / overlay 無し / 正常起動（= SI-5 disarm 試験）
```
効果は**次回起動**から。以後 `gms_stage` を再作成しても mount 3 行が存在しないため暴発しない。

---

## 6. 未確定点（実験で潰す）

1. **init が `/data` を `restorecon(_recursive)` するか**（SI-2 の成否）。
2. merged root のラベルは何で決まるか（最上位 lower / mountpoint / upper）→ 実測 `ls -Zd`。
3. fscrypt(DE) ディレクトリを overlay の lower/upper に使えるか（`EINVAL` の真因）。
4. `.rc` に `chcon` があるか。
5. 容量配分（/cache 89M に入るのは XML+GSF(〜4M) のみ。GMS 100M/Phonesky 31M は /data 必須）。
6. PM が「毎ブート常在するシステムアプリ」を一貫に扱えるか（SAFETY 文書の破壊は overlay 常在で解消しうる）。
7. **loadavg 28** の正体（watchdog リセット素地）。

---

## 7. 検証計画（1 変更 = 1 検証）

| 段 | 変更 | 検証 |
|---|---|---|
| P0 | 本設計を文書化 | 本ファイル |
| **P1** | **無害化（marker 書き込み）** | 読み戻し sha + 再起動で正常起動（SI-5） |
| P2 | 実行時 overlay 実験（boot に触らない） | `ls -Zd`（ラベル継承）、`dumpsys package`、`/data` upper EINVAL 切り分け |
| P3 | 最小ディレクトリ（/system/etc/sysconfig のみ）を `.rc` で boot 時 mount | コールドブート成功・PM 健在・`ls -Zd` |
| P4 | permissions → priv-app へ拡大 | GMS/GSF/Play = PRIVILEGED、15分安定性 |
| P5 | 文書化＋ push | repo |

各段の後、**SI-5（staging を消して再起動）**を実施して disarm を確認する。
