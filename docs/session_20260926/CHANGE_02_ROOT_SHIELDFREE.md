# CHANGE 02 — `--root2`/`--root-gms2`: シールド無し complete root [--root2 検証済み]

## 目的
change 01 で確立した「シールド無し合法 root」を、complete root（`mount(2)` + 4755 shell）に統合する。
`--root`/`--root-gms` は**そのまま残し**、新モード `--root2`/`--root-gms2` を追加（`g_shieldfree`）。

## 差分（`src/ghostlock_mrx_e.c`）
| 箇所 | 変更 |
|---|---|
| グローバル | `static int g_shieldfree;` を先頭に追加 |
| dispatch | `--root2`/`--root-gms2` を受理し `g_shieldfree=1` |
| child commit | `setresuid(0,0,0)` → `setresuid(0,0,1)`（cap_path に載せる） |
| MAIN（旧 shield+uidzero） | shieldfree 時は `arm_write_inproc(g_blackval, C+0x38, 0)` に置換（CAP_SETUID を cap_effective に） |
| `build_v2` | shieldfree 時は `g_blackval=base+0xB8` の強制をやめ、`a&0x80`（bit7=CAP_SETUID）のスロットを保持 |
| `root_cap_value` | 事後 CAP_SYS_ADMIN 用に bit21 の node（従来どおり） |

## 結果（`--root2`, 実機）[MEASURED]
- `setresuid(0,0,1) -> 1発成功`、`child POST uid=0 euid=0 suid=1 ctx=shell`。
- 事後 cap 注入で `CapEff` に CAP_SYS_ADMIN、`mount(tmpfs,'/mnt') rc=0`。
- uid-2000 が 4755 `/mnt/glsh` を exec → `euid=0(root)`（= non-nosuid tmpfs）。
- **pid-0 タスクが存在しない**（uid-0 child は実 pid）。panic 無し、リセット無し。
- 証拠: `../evidence/CHANGE02_root2.txt`。

## 未解決（`--root-gms2` の前に）
- **mount base が非決定**：今回 `/data/local/tmp/glrt` が EACCES（cap_effective に CAP_DAC_OVERRIDE(bit1)
  が無かった）→ `/mnt` が採用。`--root-gms` は `B=/data/local/tmp/glrt/gms` をハードコード。
  ⇒ GMS 用には cap 値に **bit1(CAP_DAC_OVERRIDE)+bit21(CAP_SYS_ADMIN)** を要求する
  （`root_cap_value` の要件を `0x200002` に）か、base 非依存の staging 経路にする。

## 次の変更
`--root-gms2` を検証（GMS overlay 3本 + `ctl.restart zygote` をシールド無しで）。成功後、
既定の `--root`/device スクリプトを shield-free に切替え、15分安定性を確認する。

## `--root-gms2` 結果（実機）[検証済み]
- **base 非決定の修正**: `g_root_path`（`<base>/glsh`）から実際の tmpfs base を導出し、
  `gms_setup.sh` に `$1` で渡す（既定は従来の `/data/local/tmp/glrt`）。`gms_setup.sh` も
  `B="${1:-/data/local/tmp/glrt}/gms"` に変更。
- `root_cap_value()` の park 回数を 12 → **40** に増やし、bit21(CAP_SYS_ADMIN) の取得を安定化。
- 実測（cold boot → perf=-1 → `--root-gms2`）:
  ```
  root: gms overlays base=/data/local/tmp/glrt priv=0 perm=0 sys=0 errno=0
  root: gms done (framework restarting)
  /proc/mounts upperdir=.../glrt/gms = 3
  GMS/GSF/vending = PRIVILEGED ×3
  pid-0タスク無し（uid-0子は実pid）・uptime継続・perf=-1
  ```
- 証拠: `../evidence/CHANGE03_rootgms2.txt`。
- 留意: `ctl.restart zygote` は**フレームワークのみの再起動**（カーネルは再起動しない）。
- 残: CAP_SYS_ADMIN 値の決定性（park 確率依存）。最終的には静的 `.data` 候補で確定化したい。
