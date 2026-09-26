# RAW-SUPER PERSISTENCE — findings & risk (MRX-W09, 2026-09-26)

## 背景
「native GMS の永続化」を諦めず、カーネルソース監査で見つけた
「**runtime dm-verity が改ざんブロックを最初の3個まで黙認**（`dm-verity-target.c:300-316`、
`kernel_restart` がコメントアウト、`verity_handle_4.14.c:217-243` が `return 0`）」
を起点に、実機で書込可否を調べた。

## 実測（すべて MRX-W09 / 11.0.0.235）
- `/` = `dm-6`（`system-verity`, erofs, ro）。`dm_verity` ロード済み。
- `dm-0` = `system`（verity の背後の linear）→ **書込 EPERM（ro）**。
- `/dev/block/sdd71` = **物理 `super`**（LP metadata は offset 4096 の `gDla`, version 10.0）。
  - `lpdump /dev/block/by-name/super`:
    `system = 0 .. 6389759 linear super 4096` ⇒ **system は super の byte offset 2 MiB から**、~3.27 GB。
  - **物理 super への書込みは rc=0 で成功**（同バイト, 8.4 MB/s）＝**kernel/フラッシュは物理 super への write を拒否しない**。
- `verifiedbootstate=green / flash.locked=1 / vbmeta.device_state=locked`（AVB 有効）。

## 何が可能か（仮説）
- **dm-0 は ro だが物理 super は書ける** ⇒ verity をバイパスして **system の生データブロックを書換可能**。
- verity は1ブロック改ざんを黙認 ⇒ **既存 `/system` ファイルのデータブロックを同一サイズで置換**すれば
  **再起動後もその内容が読まれ、起動も通る**見込み。
- 永続化の筋: 起動時に exec される既存 `/system/bin/<binary>` を我々の静的 ELF に置換 →
  起動時に我々のコードが走る（ドメイン次第で overlay を張れる）。
  - 第一候補: `/system/bin/tzdatacheck`（post-fs-data で確実に走る・壊れても影響小）。
  - ただし **mount 権限はドメイン依存**。最も広いのは init。root daemon（vold等）はその限りでない。

## リスク / 復旧（重要）
- **factory reset では /system 破損は直らない**（/data,/cache のみ消去）。⇒ **reflash 必須**。
- 復旧手段（手元の純正ファームあり）:
  - eRecovery（ネット, 現行 235 を取得）… 最も安全。
  - dload（SD に `UPDATE.APP`＝**210**）… **anti-rollback で拒否の可能性**。
  - fastboot flash（stock 署名なら可 / FBLOCK 制限）。
- 壊してはいけない領域: **EROFS メタデータ / verity ハッシュツリー / LP メタデータ / vbmeta / misc**
  （これらを壊すと復旧が難しくなる）。**データブロックのみ**を触る。
- 安全策: **対象ブロックを事前に退避**（super から読む）→ 起動さえすれば書き戻せる。

## 未解決（PoC 前に要検討）
1. 対象ファイルの **system イメージ内データオフセット**の特定（EROFS 解析 or raw 検索）。
2. 置換先ドメインが **mount できるか**（できなければ overlay 永続化にならない）。
3. 置換ELFのサイズ一致（同一ファイルサイズ内に収める）。
4. 210/235 の差異（手元ファームは 210、実機は 235）。

## 判定
- **物理的には可能**。ただし **EROFS オフセット特定＋対象選定＋ブリックリスク**を伴う**研究開発**で、
  「factory reset では戻らない／reflash が要る」レベルの作業。**1変更=1検証**で段階を踏むなら別セッション相当。

## 最終判定（2026-09-26 追記）: SELinux により DEAD
- CIL 実測:
  - `(allow init system_file (dir (mounton)))` … **system_file に mount できるのは init だけ**
  - `(allow init fs_type (filesystem (mount ...)))` … fs_type mount も init だけ
  - `(allow vold labeledfs ...)` … vold は labeledfs/sdcard/tmpfs のみ
  - `(neverallow appdomain fs_type (filesystem (mount ...)))`
- 起動時の exec バイナリは**全て専用ドメインに遷移**（`plat_sepolicy.cil` の
  `typetransition init <x>_exec process <x>` 群。init に残るものは無い）。
- ⇒ boot バイナリを置換しても **mount 権限が得られない** ⇒ **overlay の永続化は不可**。
- 唯一の例外は `/system/bin/init` 自体の置換だが、init の役割を再実装できず**通常起動が壊れる** → 非現実的。
- **結論: 物理 super を書く必要は無い（=ブリック回避）。この永続化ルートは DEAD。**
- 残る現実解: **毎ブート復元**（素材は `/data` 恒久／各ブートは overlay＋rescan のみ／アプリ1操作 or DO完全自動）。

