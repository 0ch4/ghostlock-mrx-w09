# CHANGE 01 — シールド無しの合法 root（安定化の核心）[検証済み: 実験]

> 結果（2026-09-26, 実機）: **pid-0シールド無しで uid=0 に到達し、そのタスクが panic せず終了**。
> 証拠は `../evidence/CHANGE01_legalroot.txt`。実装は `../src/ghostlock_mrx_e.c` の新モード
> `--legalroot`（+ `persist_proof()` の mksh 構文バグ修正）。詳細は §8。

対象: MRX-W09 / GhostLock 移植。権威: pushed `ghostlock-mrx-w09@d602d4c` の
`docs/static-analysis/TASK_PID0_RISK_20260926.md` / `docs/BREAKTHROUGH_FULL_ROOT_20260926.md`。

## 0. 命題
`pid-0` シールド（`task->pid=0` による HKIP 免除）は **任意の致命 signal で kernel panic**
する landmine（`kernel/exit.c:786`）。現 `--root` はこれを土台にしている（`ghostlock_mrx_e.c`
4897-4901 で `X+0x820` を leaf-zero、4899 で `C+4` を zero、4887 で `su_server/for(;;)`）。
⇒ シールドを外し、**permissive + cap_effective + setresuid(0,0,1)** で
`commit_creds → hkip_update_xid_root` に **実 pid の HKIP bit** を書かせて合法 root を得る。

## 1. 根拠（すべて pushed / 検証済み）
- [実測] `FACTS 9an(17)`: `cap_effective` は HKIP に**不可視**（HKIP は
  uid/euid/suid + cap_inheritable/permitted（+fsuid）のみ参照）。
- [実測] `TASK_PID0_RISK §3.1`: `commit_creds → hkip_update_xid_root → hkip_set_task_bit` は
  **pid!=0 なら bit を書く**（pid==0 のみ no-op）。
- [実測] `FACTS:772,890,2040,2075`: `setresuid(0,0,1) → commit_creds → hkip_update_xid_root → our bit`。
- [実測] `FACTS:1571`: `--endgame3` は cap 書き込みまで成功（`eff=...CAP_SETUID=1`）。
  当時 `setresuid -> -1 uid=2000` だったのは **SELinux capability ゲート**が enforcing だったため。

## 2. 既存の部品（コード変更なしで使える）
| モード | 行 | 役割 | シールド |
|---|---|---|---|
| `--freeze` | 4334 | MCAST で fake ebitmap node を park し、permissive_map を patch。`for(;;) pause()` で node を常駐維持 | **無し** |
| `--endgame3` | 3463 | T→C リーク、`cred->cap_effective=g_blackval`(bit7)、`setresuid(0,0,1)`、`persist_proof()` | **無し** |

`--endgame3` の成功時メッセージは既に `[+] ... LEGAL ROOT`。

## 3. 検証手順（1ラン・短時間）
**前段（perf を立てる。通常の PC-less 手順）**
1. コールドブート（perf=3, hook 無し）。
2. `/data/local/tmp/shellcode.bin`（payload）と `glboot.sh` を配置。
   **この実験では `glboot.sh` を「stage1=perf 書き込みのみ／stage2=no-op」に差し替える**
   （自動で `--root-gms` の landmine を作らせないため）。
3. `inject_hook place 0x84000 <size-4> 0x7a3d8` / `inject_hook hook 0x7a3d4 0x84000`。
4. `nohup /system/bin/bugreportz &`（**1回だけ**）。
5. `cat /proc/sys/kernel/perf_event_paranoid` == -1 を確認。以後 `.glp2` claim 済みで
   adb shell は payload を再発火しない（マーカーが守る）。

**本段（シールド無し root）**
6. `nohup /data/local/tmp/ghostlock_e --freeze > /data/local/tmp/gl.freeze.out 2>&1 &`
   → oracle で `PERMISSIVE MAP LIVE` を確認（park したまま生存させる）。
7. `/data/local/tmp/ghostlock_e --endgame3 > /data/local/tmp/gl.eg3.out 2>&1`
   （**foreground**。終了する）。

## 4. 受入（この1ランで全部見る）
1. `eg3.out` に `setresuid -> 0 uid=0`（= commit_creds 到達）。
2. `--endgame3` プロセスが **正常終了** し、**panic しない**（= シールド無しの証明）。
3. `rooted.txt` / proof が uid 0 で作成される。
4. その後 `uptime` が伸び続け、**15分自発リセットしない**。
5. できれば追加で `--endgame3` をもう一度走らせ、2回目も panic しないことを確認。

## 5. 途中で panic した場合の読み
- `adb shell dumpsys dropbox --print SYSTEM_LAST_KMSG` は **truncate** される。
- pstore は root-only。panic 直後の最初のブートで restore する前に読む（上書き注意）。

## 6. 成功した場合の統合（次の変更）
- `--root` から `--simple`（シールド）を外し、`--endgame3` の cap+setresuid を土台にする。
- その child は **exit 可能**なので、`su_server/for(;;)` の「絶対に終了しない」制約が消える。
- GMS overlay（`--root-gms`）は、合法 root を得た後にそのまま実行。

## 7. リスク / 未確定
- `--freeze` の park 窓は process 生存中のみ有効。`--freeze` を落とすと permissive_map が
  dangling になり AVC walk が panic し得る（**落とさない**）。
- `--endgame3` の T リーク（x22）と boot_id read の安定性（`FACTS 9an(15)` は reliable と記載）。
- `--freeze` と `--endgame3` の実行順・同一ブート内の相互作用は未実測。

## 8. 結果（実機・2026-09-26）[MEASURED]
- `--endgame3` は **単発walkの x22 リークが弱く**（`samples=3 in_chain=0`）失敗 → リークだけ
  `leak_own_cred_x0`（x25ストーム）に差し替えた新モード **`--legalroot`** を実装。
- 手順: cold boot → perf専用 payload で perf=-1 → `--freeze`（permissive LIVE, park）→
  `--legalroot`。
- 実測:
  ```
  legalroot: C=0xffffffceec129b40
  legalroot: cap_effective w=0 value=0xffffffcedb31bc90 low=90   (bit7=CAP_SETUID)
  legalroot capget eff=ffffffcedb31bc90 SETUID=1
  legalroot setresuid(0,0,1) -> r=0 errno=0 uid=0
  [+] legalroot: UID 0 -> commit_creds -> HKIP bit (LEGAL ROOT, exit-safe)
  proof: rooted.txt = uid=0(root) ctx=u:r:shell:s0 / rsh = 4755 root
  ret=0, --legalroot プロセスは消滅, uptime 継続, panic 無し
  ```
- 副次修正: `persist_proof()` の `echo ... (HKIP ...) ...` が未クォートで **mksh の構文エラー**
  だった（rooted.txt が書けない原因）。`'...'` でクォートして修正。

## 9. 次の変更（統合）
`--root` の child から **shield（`X+0x820`）と cred uid-zero（`C+4`）を撤去**し、
`--legalroot` と同じ「cap_effective(bit7) → `setresuid(0,0,1)`」に置換する。
cap値は bit7 と bit21 の両方を持つアドレスを1つ選べば、commit前後で兼用できる
（`root_cap_value()` のマスクを `0x200080` に）。そのうえで `--root-gms` を再検証。
