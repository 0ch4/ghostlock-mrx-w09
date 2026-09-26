# RECONCILIATION — 権威ある基準の再固定と劣化文書の切り分け（2026-09-26 後半）

この文書は session 劣化で混入した不正確な記述を切り分け、**push 済み repo を権威**として
現在地と次の1変更を固定するためのもの。推測は書かず [実測] / [未検証] / [劣化] を付す。

---

## 0. なぜ必要か
直近の `HANDOFF.md §11` と `MRX_W09_GHOSTLOCK_FACTS.md 9an(169)/(170)` は、
**既に push 済み repo が確立していた結論を再litigationし、限定された誤った原因に還元**している。
（例：panic の引き金を「init ExitCatch の pgid kill」と断定するが、根拠の pstore は §11.2 自身が
「別ブートで上書き済み」と書いている。）
⇒ 以後、**push 済み repo と検証済み FACTS(≤9an168) を正**とし、直近文書は「検証対象」とする。

---

## 1. 権威ある基準（これを正とする）
| 種別 | 場所 | 内容 |
|---|---|---|
| 公開 repo | `F:\testtest\publish\ghostlock-mrx-w09` @ `d602d4c` (2026-09-26 11:16) | README / docs/FACTS.md（≤9an168）/ docs/static-analysis/* |
| 公開 repo | `F:\testtest\publish\ghostlock-mrx-w09-gms` @ `7e4c32c` | GMS 手引き / scripts |
| 最重要 doc | `docs/static-analysis/TASK_PID0_RISK_20260926.md` | pid-0 シールドの全危険性（§0, §3, §4.6） |
| 最重要 doc | `docs/BREAKTHROUGH_FULL_ROOT_20260926.md` | route 1（cap_effective 注入）と §6 制約 |
| 最重要 doc | `docs/static-analysis/TASK_CRED_OFFSETS_20260926.md` | cred/task オフセット |
| 最重要 doc | `docs/static-analysis/TASK_WRITE_SHAPE_20260926.md` | write primitive の形状 |
| ホスト素材 | `F:\testtest\host_material` | mtg_stage / dev_ghostlock_e / dev_shellcode.bin / INSTALL_PLAN.ps1 |

`git ls-remote` で確認済み [実測]：main=d602d4c998118851daad32e860cd26c8a810402f /
gms=7e4c32c0891e1c4c7ebc1d99a515492b9177c521。

---

## 2. 劣化（要検証扱い）— 何を信用しないか
| # | 文書 | 主張 | 判定 | 根拠 |
|---|---|---|---|---|
| 1 | `HANDOFF.md §11.1` | panic 引き金＝init `ExitCatch` がプロセスグループを SIGKILL（高確度） | **[劣化/未確定]** | 引用 pstore は §11.2 自身が「新ブートの 95〜118 秒で上書き、panic 本体は失われた」と記載。**別ブートのログ**で因果を断定 |
| 2 | `HANDOFF.md §11` の `setsid` 修正 | これで panic が消える | **[未検証]** | 殺し手を1つ潰すだけで、TASK_PID0_RISK §4.6「任意の致命 signal で panic」を除去しない |
| 3 | `HANDOFF.md §11.3` | boot_id は不安定 → `btime` に変更 | **[未検証]** | 二重起動（`ovl=6`）はロック層の問題。panic とは別問題として分離すべき |
| 4 | `FACTS 9an(169)` | panic＝メモリ圧迫（低メモリ経路が pid-0 を kill） | **[否定済み]** | 9an(170) が `oom_score_adj=-1000`/`MemAvailable 2.7〜3.7GB` で否定 |
| 5 | `FACTS 9an(170)` | panic の引き金は不明 | **[部分的]** | 完成品 `TASK_PID0_RISK` が「pid==0 は exit 不可・任意 signal で panic」と既に結論済み |

---

## 3. 再固定した論理（正しい理解）
1. **panic は設計上の必然**：pid-0 シールド task は `do_exit` の
   `if (unlikely(!tsk->pid)) panic("Attempted to kill the idle task!")`（`kernel/exit.c:786`）
   に必ず当たる。**任意の致命 signal（外部 `kill -9`、HKIP の `force_sig(SIGKILL)`、OOM、
   framework 再起動に伴う kill 等）で panic** [TASK_PID0_RISK §0/§4.6]。
   ⇒ 引き金を数え上げるのは不毛。**シールドを critical path から外すのが唯一の安定化**。
2. **シールド無しで合法 root に到達する道が既にある**：
   shell 型 permissive ＋ `cred->cap_effective`（HKIP 不可視）＋ `setresuid(0,0,1)`
   → `commit_creds` → `hkip_update_xid_root(new)` が**実 pid に HKIP bit を書く**
   → 合法 uid 0（exit 可能、fork 子も合法）。
   - [実測] `FACTS 9an(17)`：`cap_effective=CAP_SETUID` は HKIP に不可視（1.6s 無反応）。
     HKIP の判定は uid/euid/suid ＋ cap_inheritable/permitted（+fsuid）で **cap_effective を見ない**。
   - [実測] `TASK_PID0_RISK §3.1`：`commit_creds → hkip_update_xid_root → hkip_set_task_bit` は
     **pid!=0 で bit を書く**（pid==0 のみ no-op）。
   - [実測] `FACTS:772,890,2040,2075`：`setresuid(0,0,1) → commit_creds → hkip_update_xid_root → our bit`。
   - [実測] `FACTS:1571`：`--endgame3` は cap 書き込みまで成功。当時 EPERM だったのは
     **SELinux capability ゲート**が生きていたため（permissive 化で解消）。
3. **後退の正体**：現 `--root` が `--simple`（= pid-0 シールド + cred uid 直書き）を土台にしている点。
   シールド無しの cap 経路（上記 2）は部品として存在するのに、統合 `--root` がシールドを抱えている。
4. cap 上書きは「値を encode する」のではなく **low32 に欲しいビットを持つカーネルポインタを選ぶ**
   （`BREAKTHROUGH_FULL_ROOT §2`）。bit21=CAP_SYS_ADMIN、bit1=CAP_DAC_OVERRIDE、bit7=CAP_SETUID 等。

---

## 4. 第一の変更（1変更 = 1実機検証 = 1記録）
**変更**：シールド無しで「permissive(shell) → cap_effective（CAP_SYS_ADMIN ほか）→ `setresuid(0,0,1)`」
を実行する経路を1つ用意する。
**受入（この1ランで全部見る）**：
1. `id` が `uid=0`（かつ `capget` の CapEff に bit21）。
2. そのタスクを**自分で exit** させても panic しない（= シールド無しの証明）。
3. fork した子が uid 0 でファイルを作成できる（= HKIP bit が実 pid に立っている証明）。
4. `mount(2)` rc=0（非 nosuid tmpfs）。
**失敗時**：hook は RAM のみ、再起動で消える（rollback 不要）。
**禁止（維持）**：同一ブートで exploit を2回走らせない / `inject_hook restore` を同一ブートで呼ばない /
hook ON のまま長い adb 操作をしない。

---

## 5. この再固定でも残る未解決
| # | 問題 | 扱い |
|---|---|---|
| 1 | 二重起動（`ovl=6`） | 安定化とは分離。ロック層の改善（`btime` or payload 側）で別途1変更 |
| 2 | マーカー残留（`.glp0/.glp2`） | payload/script 側の lifecycle で別途 |
| 3 | YouTube `READ_GSERVICES` | GSF 常駐後インストールで付与（gms_repo 手引き） |
| 4 | Play 自己更新 → `/data` コピー特権喪失 | 自動更新 OFF 前提 |
| 5 | APK `busy` 全ボタン共通バグ | oneshot 化で修正 |
| 6 | triger タップ数の下限 | アプリの `/system/bin/bugreportz` exec 可否を実測（`9an(164)A` vs `9an(160)C` の矛盾） |
| 7 | 高速化（`ctl.restart zygote` 支配） | 時間内訳を1ラン計測 |

---

## 6. 進め方
- 常に shell は **foreground** 実行。
- 変更は push 済み repo の記述と突き合わせ、食い違いは本ファイル or FACTS に記録。
- 1変更ごとに commit（説明付き）。

---

## 7. 成果物のドリフト（pushed repo ↔ ローカル）[実測]
| 成果物 | pushed repo | ローカル | 判定 |
|---|---|---|---|
| `exploit/ghostlock_mrx_e.c` | `--root-gms` **無し** | `--root-gms` **有り**（publish + 50/-4 行） | pushed の README §13 / gms 手引きは `--root-gms` 前提 → **pushed exploit は古い** |
| `scripts/gms_restore.sh` | 4033 B（gms repo） | `session_20260922/gms_restore.sh` 6892 B（デバイス実体） | デバイス版が最新。pushed は途中版 |
| `gms_repo/scripts/*` | - | `gms_repo` は pushed と同一内容（uncommitted 差分） | 実質同期済み |
| `docs/FACTS.md` | ≤9an168 | 9an169/170 を追記 | 追記分は §2 のとおり **要検証** |
| `docs/static-analysis/TASK_PID0_RISK` | **有り**（panic の必然を明記） | - | pushed が権威 |

⇒ **コードはローカル最新を baseline に、論理/オフセットは pushed を baseline に**する。
作業フォルダの `baseline/main`（pushed）と `baseline/main-local`（ローカル最新）に両方を凍結済み。

---

## 8. 第一変更の候補（コード変更なしで検証可能）[未検証]
`--freeze`（permissive を立て park 継続・**シールド無し**）→ `--endgame3`
（cap_effective=bit7 → `setresuid(0,0,1)` → `commit_creds` → `hkip_update_xid_root` → HKIP bit）。
`--endgame3` は当時 EPERM だったが、それは **permissive が生きていなかった**ため。
⇒ 詳細は `docs/CHANGE_01_SHIELD_FREE_ROOT.md`。
