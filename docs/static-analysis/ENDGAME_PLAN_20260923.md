# GHOSTLOCK / MRX-W09 (Kirin 990, 4.14.116, EMUI 11) — ENDGAME PLAN & STATE

作成: 2026-09-23 / `binder_uaf/session_20260922/ghostlock_mrx/ghostlock_mrx_e.c` 作業分

---

## 1. ゴール（未達）
`/data/local/tmp/rooted.txt` と 4755 `/data/local/tmp/rsh` を **uid-0 root ＋ HKIP bit** で生成し、
`rsh -c id` で検証する。

## 2. 実機で確立済みの primitive（すべて検証済み）
| primitive | 内容 | 備考 |
|---|---|---|
| VALUE write | `*(target) := value`。value は「先頭ワードが奇数(bit0=1)の読めるカーネルアドレス」 | side store は `(value&~3)+8 / +0x10` に落ちる |
| LEAF ZERO write | `{pc=target-8, right=0, left=0}` → `*(target或いはtarget+8) := 0` | `--leaf0` で検証 |
| boot_id READ | `do_write(A, g_bootid_df)` → sysctl 読みで `*(A)` の16バイトが漏れる | 16バイト読み |
| re-arm multi-walk | 1アームで複数ウォーク可（`--rearmN 6` = 5/6） | cold streak あり |
| cred アドレス復元 | 2つの disposable consumer で `*(T+0x9E8)` の上位/下位を読む（`--readP`） | 反復成功 |

## 3. HKIP の実体（公開実ソース＝Impalabs 2022 と一致）
```c
int hkip_check_uid_root(void){
    if (hkip_get_current_bit(hkip_uid_root_bits, true)) return 0;   // pid==0 は def_value=true
    creds = current_cred();
    if (unlikely(hkip_compute_uid_root(creds) || uid_eq(creds->fsuid,0))){
        pr_alert("UID root escalation!\n"); force_sig(SIGKILL, current); return -EPERM; }
}
hkip_compute_uid_root = uid==0||euid==0||suid==0||cap_inheritable!=0||cap_permitted!=0
#define DEFINE_HKIP_TASK_BITS(name) DEFINE_HKIP_BITS(name, PID_MAX_DEFAULT) // ROWM 保護
#define HKIP_HVC_ROWM_SET_BIT 0xC6001050
```
- bit は `commit_creds()→hkip_update_xid_root()` と `copy_process()→hkip_init_task()` でのみ立つ。
- `HKIP_HVC_ROWM_SET_BIT(uid_root_bits,pid,1)` が唯一の直接設定路（EL1 から HVC）。bitmap は ROWM で EL1 書き込みは fault。
- **cap_effective は判定に含まれない** → `cap_effective=CAP_SETUID` は HKIP 完全不可視（実機実証）。

## 4. 実測した障害（重要）
1. **SELinux 第二関門**（実測）:
   ```
   avc: denied { sys_nice }  capability=23 scontext=u:r:shell:s0
   avc: denied { sys_admin } capability=21 scontext=u:r:shell:s0
   setresuid(0,0,1) → -1 (EPERM)  ※cap_effective に CAP_SETUID あり
   ```
   → shell ドメインは `capability setuid` を持たない。`cap_effective` では突破不能。
2. **cred 直接書き換えは panic を招く**（pstore 解析）:
   ```
   spin_bug <- do_raw_spin_unlock <- rt_mutex_adjust_prio_chain+0xa88
   UID root escalation!  (root 化の約0.2秒後)
   fault at 23c9cfe8_8eae9c00 (下位32bit==P の下位32bit)
   PC=exit_creds+0x80  LR=__put_task_struct+0x124  → Kernel panic
   ```
   真因: `--readP` の LOW 読みが対象 consumer の `real_cred+4`（上位半分）を上書き → **kill されると
   teardown で破損 cred を put して fault**。＝**kill されなければ無害**。
3. **kernel ドメインは `shell_data_file` に書けない**（`--pid0win` 実測）。`setcon`（kernel→shell）も拒否。

## 5. 到達済みの状態
- `uid 0 + full caps + u:r:kernel:s0`（`--pid0win`、`/proc/PID/status` で実証）＝ただしファイル不可。
- `uid 0 + shell SID` は未達（cred 書き換えの安全性の問題）。
- HKIP bit は未達（`commit_creds` 到達が SELinux で阻まれる）。

## 6. 次プラン（優先順）
### 6.0 確定した追加事実（2026-09-24）
- **HKIP の 2 種のチェックの違い**（実測からの帰結）:
  - `hkip_check_uid_root`（uid/euid/suid/cap_inh/cap_prm/fsuid を見る）は **`task_pid_nr()` を使う**ため、
    我々が書き換えた cached `task->pid`(+0x820) では回避できない → root 相当タスクは ~0.2 秒で SIGKILL。
  - 一方 `hkip_check_xid_root` 系（arm/scheduler 経路で MAIN が踏むもの）は **pid==0 速路が効く**。
    これが `--pid0win` で root 相当の main が生き延びた理由。
- **leaf-zero は cred に対してクリーンなゼロにならない**（実測: `uid` に `P>>32` のゴミ）。
  → 目的「cred identity tuple をゼロ化」は leaf 形では実現不可。

### Plan A（uid 先行 → setresuid フォールバック）: **不可能**（除外）
理由: (a) leaf で uid をクリーンにゼロ化できない、(b) `setresuid` は無条件に `ns_capable()` を呼び、
フォールバックが効く条件（既に uid==0）は HKIP が殺す状態そのもの。

### Plan B-1: `--getbit`（実装済み・検証中）— 目標の「bit requirement」を満たす
kernel SID ＋ cached pid=0 ＋ **即 setresuid(0,0,1)** → `commit_creds` → `hkip_update_xid_root` → bit。
証明: bit 無し root は ~0.2 秒で殺されるので **uid 0 のまま 2 秒生存＝bit 有り**。
（この段階の SID は kernel なのでファイルはまだ書けない）

### Plan B-2: shell SID へ差し替えてファイル生成（次の実装対象）
1. `--getbit` まで到達（uid0＋全caps＋bit）。
2. 旧補助スレッドを SIGSTOP（以後 P を誰も参照しない）。
3. `S = *(P+0x78)` を byte-shift 読み → **`shell SID = *(S+4)`** を読む
   （P は誰も使わないので副作用 P+0x7C/0x80 は無害。S+3 読みの副作用は S+8/S+0x10 のみ）。
4. **新 consumer**（main の private cred を共有）で残りのアームを着火。
5. **prober スレッド**（main の cred を共有）の `*(Tprober+0x9E0)` を読み、**現在の cred C** を得る
   （clobber は prober 側だけ＝main 無傷）。
6. `cred->security = window ブロブ(sid=shell)` を C+0x78 に書き込み → **uid0＋全caps＋bit＋shell SID**。
7. `rooted.txt` 生成 ＋ `/system/bin/sh`→`rsh` ＋ chmod 4755 → `rsh -c id` 検証。

### Plan C: HKIP bit を HVC で直接立てる（公開 ROP レシピ）
`HKIP_HVC_ROWM_SET_BIT` を kernel 内で呼ぶ。要 kernel 呼び出し primitive。難度は高い。

### Plan D: AVC キャッシュ汚染 / permissive domain
policydb/avc のアドレスが必要で難度は高い。

## 7. 依存する既知オフセット
`TASK_REAL_CRED=0x9E0`, `TASK_CRED=0x9E8`, `TASK_PID=0x820`, `cred->security=+0x78`,
`cred->cap_effective=+0x38`, `cred->usage=+0`, `INIT_CRED=0xffffff800adfcd28+g_slide`.

## 8. 注意（運用）
- `panic_on_oops=1` → oops は即 reboot。`--pid0win` は `panic_on_oops`/`kptr_restrict` を先に零化する。
- `task->pid`（cached, +0x820）を 0 にしたタスクは **絶対に exit してはならない**（`do_exit` が panic）。
- 1変更 → 1実機検証 → 1コミット。pstore は毎回読む。
