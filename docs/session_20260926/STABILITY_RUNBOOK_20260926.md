# STABILITY RUNBOOK — 2026-09-26 (MRX-W09)

目的: 復元後 **15分** watchdog リセットが出ないことを確認する。出る場合は**引き金**を特定する
（現状の有力仮説: **PiP 起動**。watchdog の hungtask は `system_server`/`surfaceflinger`/`init`）。

---

## 0. 用語 / 前提
- 「watchdog リセット」= `getprop sys.boot.reason` が `reboot,abnormal` 等（`reboot,adb` 以外）。
  カーネルメッセージ: `hungtask: whitelist[...]-system_server/surfaceflinger/init` ＋ `sp805-wdt`。
  **pid-0 panic ではない**（shield-free で除去済み）。
- overlay は 1ブート限り。復元は「arm → 1トリガ → 約5秒で overlay 3/3 → +30〜60秒で PRIVILEGED」。
- **同一ブートで exploit を2回走らせない**。**hook ON の間は余計な adb shell をしない**（one-shot 消費）。

---

## 1. 15分安定性テスト
1. コールドブート。`T0` = ホーム表示。
2. 復元（どちらか）:
   - アプリ:「★ 復元(1操作)」→ a11y が `バグレポートを取得`→`完全レポート`→`報告`。
   - adb: `inject_hook place/hook` → `nohup /system/bin/bugreportz &`。
3. `T_restore` = overlay 3/3 を確認した時刻（`grep -c "overlay /system/priv-app" /proc/mounts` が 1）。
4. **`T_restore + 15分` まで待つ**。この間、端末で普通に使ってよい（YouTube/PiP なども試す）。
5. 判定:
   - `uptime` が 15分以上伸び、`sys.boot.reason=reboot,adb` のまま → **合格（安定）**。
   - 途中でリセット → **§2 へ**。

## 2. リセット時の原因取得（hungtask スタック）
> pstore は **root のみ**、かつ**新しいブートのコンソールで約95秒で上書き**される。急ぐ。

リセット後の最初のブートで:
1. **最速で復元**する（アプリ or adb。root を得る）。
2. すぐ（上書き前に）:
   ```
   su -c "cat /sys/fs/pstore/console-ramoops"     # 前回ブートの全カーネルログ
   su -c "cat /sys/fs/pstore/dmesg-ramoops-0"
   ```
   - SELinux で拒否されたら exploit の uid-0 子（`/data/local/tmp/su -c ...`）から。
   - 取れなければ `adb shell dumpsys dropbox --print SYSTEM_LAST_KMSG`（**truncate される**が hungtask 行は残る）。
3. 見る場所: `hungtask:` / `Call trace:` / `InitWatchdog` / `sp805-wdt` / `[pid:..,cpu..,<task>]` の
   **ブロックしているタスクとスタック**。

## 3. PiP 仮説の再現（任意・原因が watchdog のとき）
1. 復元後、YouTube（または PiP 可能アプリ）を開く。
2. **PiP に入れる**（ホームへ戻る / PiP ボタン）。
3. 数秒〜数十秒で watchdog が飛ぶか観察。飛んだら §2 でスタック取得。
- もし PiP で再現するなら、`SurfaceFlinger` と overlay/root 状態の相互作用を調査（別途 1変更）。

## 4. 記録
- 結果は `evidence/` に追記（`CHANGE07_stability_*.txt`）。
- 合格なら STATUS の「残」から「15分安定性」を消す。不合格なら hungtask スタックを貼る。
