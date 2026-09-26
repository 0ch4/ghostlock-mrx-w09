# POSTMORTEM — なぜ壊れたのか（MRX-W09, 2026-09-26）

対象: CHANGE_08 の EROFS `.rc` 注入（`perfetto.rc`）後に bootloop → fastboot / eRecovery。
証拠は本リポジトリ内の実物（注入ブロック・スクリプト・ログ記録）。

---

## 結論（TL;DR）
**EROFS への書き込みは完全にクリーンだった。壊れたのは `.rc` の中身＝ overlay の張り方。**
`/system` の**中核ディレクトリ自体**に overlay を被せたため、PackageManager / system_server が
起動直後に読む「特権アプリ許可リスト」と「システムアプリ」が**ラベル不正で見えなくなり**、
zygote/system_server が起動できず bootloop → fastboot。

---

## 証拠1 — EROFS 書き込みは無罪
`perfetto_block_orig.bin` と `perfetto_block_full.bin` の実測:
- inode ヘッダ 48 バイトは **完全一致**（`04 00 02 00 a4 81 01 00 13 09 …`）。
- 差分は **inline データ域 50–2370 のみ**、単一 4096 B ブロック内。
- サイズ 2323 B 維持（payload 502 B + `#`×1821）。
⇒ メタデータ破壊なし。計画の想定リスク「オフセット誤りで EROFS メタデータ破壊」は**起きていない**。

## 証拠2 — marker は起動、full で破壊
- marker payload（`setprop gl.boot.injected 1` のみ）→ 正常起動。
- full payload（＋mount 3 行）→ 破壊。
⇒ 引き金は **mount の 3 行**に確定。

## 証拠3 — 実際に注入された `.rc`（`perfetto_block_full.bin` より）
```
# ---- persistent GMS overlay (injected) ----
on post-fs-data
    setprop gl.boot.injected 2
    mkdir /data/gls 0771 root root
    mount overlay overlay /system/etc/permissions ro lowerdir=/data/local/tmp/gms_stage/permissions:/system/etc/permissions
    mount overlay overlay /system/etc/sysconfig   ro lowerdir=/data/local/tmp/gms_stage/sysconfig:/system/etc/sysconfig
    mount overlay overlay /system/priv-app        ro lowerdir=/data/local/tmp/gms_stage/priv-app:/system/priv-app
# ---- end injected ----
```
元の `perfetto.rc`（traced / traced_probes の service 定義）は**丸ごと置換**された。

## 証拠4 — 「正しい」レシピは既に実機で動いていた
`baseline/gms/glboot.sh:19`（実績あり）
```
mount -t overlay overlay -o lowerdir=/system/priv-app,upperdir=$D/glrt2/up,workdir=$D/glrt2/wk /system/priv-app
```
差異は決定的:
| 項目 | 動いていたレシピ | 壊れた `.rc` |
|---|---|---|
| マウント先 | 中立 `/data/local/tmp/glrt2` | **`/system/*` の実体そのもの** |
| upper/work | **tmpfs 必須**（`/data`(f2fs) は EINVAL） | **無し** |
| lowerdir | `/system/...` のみ | **`/data/local/tmp/gms_stage/...` を最上位に** |
| 実行主体 | exploit の uid0 プロセス | init（`.rc`） |

---

## 欠陥（5点）
1. **overlay を `/system` の中核ディレクトリ“自体”に被せた。**
   これらは PackageManager / system_server が `post-fs-data` 直後に読む場所。ここを差し替えると
   起動そのものが壊れる。
2. **最上位 lowerdir が `/data/local/tmp/gms_stage/*`（`shell_data_file`）。**
   overlayfs のマウントルートは**最上位 lowerdir のラベルを継承**するため、`/system/priv-app` 等の
   見え方が **`shell_data_file`** になり、`system_server` が **denied** → システムファイルが「消えた」状態に。
3. **upperdir / workdir 無し（lower-only）。** サポート形ではなく、ラベル・マージ挙動が不定。
4. **`/data/local/tmp/gms_stage` は起動時に存在しない／揮発の可能性**（`/data/local/tmp` は tmp 的で、
   起動順によっては未作成）。存在しなければ「原本を含まない」マージになり得る。
5. **検証が不十分だった。** CHANGE_08 の検証は `gl.boot.injected` と `mount` の**存在**だけを見ており、
   **「システムが生きているか」**（PackageManager がシステムアプリを認識できるか）を確認していない。

## 「hid system files」の機序（推定）
overlayfs ルートのラベル継承（欠陥2）→ system_server が `/system/priv-app`
・`/system/etc/permissions` を読めない → システムアプリと特権許可が**空/拒否**に見える →
zygote / system_server 起動失敗 → **bootloop（→ fastboot/eRecovery）**。
> 注: もし mount が“失敗”していたら壊れない。**壊れたという事実そのものが「mount が効いた」証拠**。

## 併存する既知リスク（別軸）
- `STATUS_20260926.md` §27–33: **正しいレシピでも**、overlay＋`ctl.restart zygote` を高負荷で行うと
  init/system_server/surfaceflinger の hungtask で **watchdog リセット**。overlay 方式自体が本端末で不安定。
- `PERSISTENCE_RAW_SUPER_20260926.md` §47–57: boot バイナリ置換は SELinux（`mounton system_file` は
  init のみ／boot バイナリは typetransition で init を離れる）で **DEAD**。`.rc`（init ドメイン）は
  mount 可能だが、この失敗で「危険」が実証された。
- FEC 領域ゼロ化（`evidence/fec/fec_bak.bin`）は別逸脱。単一ブロック改竄は verity 許容のため
  **今回の直接原因ではない**が、在庫状態を汚した（リカバリで払拭予定）。

## 修正設計（次にやるなら）
- **`/system` の実ディレクトリには絶対に overlay しない。** 中立パスへ mount し、
  `lowerdir` は**原本のみ**、`upperdir`/`workdir` は **tmpfs** で必ず付与。
- まず**無害なディレクトリ**で 1 変更 1 検証（`ls -Zd` でラベル、`logcat` で PackageManager を確認）。
- 素材は `/data/local/tmp` でなく **`/data/gls` に置き正しいラベルへ `chcon`**。
- そもそも **boot 時 overlay は本端末では諦め、実証済みの「毎ブート復元」を採用**（STATUS の結論）。

## 確定した事実 vs 仮説
- **事実**: EROFS 書き込みクリーン ／ marker 成功・full 破壊 ／ 注入内容 ／ 正レシピとの相違 ／
  SELinux 上 init のみ `mounton system_file` 可。
- **仮説**: overlay ルートのラベル継承による system_server denied（「hid」の機序）。
  実機再現は不可（既に復旧中）のため、静的証拠＋観測（"hid system files"）からの最有力推定。
