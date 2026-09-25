#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
polpatch.py - locate and patch the SELinux *binary* policydb `permissive_map`.

Usage:
    python polpatch.py <in> <out> [typevalue]

Default typevalue = 1153 (the `shell` type on the MRX-W09 device policy).

What it does
------------
1. Walks the binary policy exactly the way the kernel `policydb_read()` does
   (`security/selinux/ss/policydb.c`), consuming every section in order:
      magic/strlen/string -> version + config + sym_num/ocon_num ->
      ebitmap policycaps -> ebitmap permissive_map -> 8 symtabs -> te_avtab ->
      cond_list -> role_trans -> role_allow -> filename_trans -> ocontexts ->
      genfs -> range_trans -> type_attr_map.
   It fails loudly unless the walk ends at exactly len(file) and no field ran
   past EOF.
2. Records and prints the byte offset of every section, in particular the
   permissive_map ebitmap.
3. Decodes the current permissive set, adds `typevalue`, re-encodes the bitmap
   in the exact on-disk ebitmap encoding the kernel/libsepol use, and splices it
   into the image (growing/shrinking the file as needed - there is no length or
   checksum field in the header).
4. Re-parses the output and asserts: (a) bit is set, (b) the walk still consumes
   the whole file, (c) the section layout is otherwise identical.

The on-disk ebitmap encoding (see ss/ebitmap.c ebitmap_read/ebitmap_write) is:
    u32 mapunit      (must be 64 = BITS_PER_U64)
    u32 highbit      (written as roundup(maxbit+1, 64); reader rounds up to 384)
    u32 count        (number of 64-bit words that have any set bit)
    count * { u32 startbit; u64 map }
        startbit = rounddown(bit, 64), map bit k -> bit startbit+k
There is NO per-node 384-bit on-disk unit; the 384-bit grouping is an in-memory
detail created by ebitmap_read when it merges consecutive entries.
"""

import sys

MAGIC = 0xF97CFF8C
POLICYDB_STRING = b"SE Linux"
BITS_PER_U64 = 64
EBITMAP_SIZE = 384

# kernel include/security.h
V_BASE = 15
V_BOOL = 16
V_IPV6 = 17
V_NLCLASS = 18
V_VALIDATETRANS = 19
V_MLS = 19
V_AVTAB = 20
V_RANGETRANS = 21
V_POLCAP = 22
V_PERMISSIVE = 23
V_BOUNDARY = 24
V_FILENAME_TRANS = 25
V_ROLETRANS = 26
V_NEW_OBJECT_DEFAULTS = 27
V_DEFAULT_TYPE = 28
V_CONSTRAINT_NAMES = 29
V_XPERMS_IOCTL = 30
V_INFINIBAND = 31
V_MIN, V_MAX = V_BASE, V_INFINIBAND

SYM_NUM = 8
SYMTAB_NAMES = ["commons", "classes", "roles", "types", "users", "bools", "levels", "cats"]
SYM_COMMONS, SYM_CLASSES, SYM_ROLES, SYM_TYPES = 0, 1, 2, 3
SYM_USERS, SYM_BOOLS, SYM_LEVELS, SYM_CATS = 4, 5, 6, 7

OCON_ISID, OCON_FS, OCON_PORT, OCON_NETIF = 0, 1, 2, 3
OCON_NODE, OCON_FSUSE, OCON_NODE6 = 4, 5, 6
OCON_IBPKEY, OCON_IBENDPORT, OCON_NUM = 7, 8, 9
OCON_NAMES = ["isid", "fs", "port", "netif", "node", "fsuse", "node6",
              "ibpkey", "ibendport"]

# policydb_compat[]: version -> (sym_num, ocon_num).  This mirrors
# security/selinux/ss/policydb.c exactly.  Lookup is "greatest version <= v".
COMPAT = [
    (V_BASE,                 SYM_NUM - 3, OCON_NUM - 3),
    (V_BOOL,                 SYM_NUM - 2, OCON_NUM - 3),
    (V_IPV6,                 SYM_NUM - 2, OCON_NUM - 2),
    (V_NLCLASS,              SYM_NUM - 2, OCON_NUM - 2),
    (V_MLS,                  SYM_NUM,     OCON_NUM - 2),
    (V_AVTAB,                SYM_NUM,     OCON_NUM - 2),
    (V_RANGETRANS,           SYM_NUM,     OCON_NUM - 2),
    (V_POLCAP,               SYM_NUM,     OCON_NUM - 2),
    (V_PERMISSIVE,           SYM_NUM,     OCON_NUM - 2),
    (V_BOUNDARY,             SYM_NUM,     OCON_NUM - 2),
    (V_FILENAME_TRANS,       SYM_NUM,     OCON_NUM - 2),
    (V_ROLETRANS,            SYM_NUM,     OCON_NUM - 2),
    (V_NEW_OBJECT_DEFAULTS,  SYM_NUM,     OCON_NUM - 2),
    (V_DEFAULT_TYPE,         SYM_NUM,     OCON_NUM - 2),
    (V_CONSTRAINT_NAMES,     SYM_NUM,     OCON_NUM - 2),
    (V_XPERMS_IOCTL,         SYM_NUM,     OCON_NUM - 2),
    (V_INFINIBAND,           SYM_NUM,     OCON_NUM),
]

CEXPR_NAMES = 5                     # ss/constraint.h
AVTAB_XPERMS = 0x0700              # AVTAB_XPERMS_ALLOWED|AUDITALLOW|DONTAUDIT
AVTAB_TYPE = 0x0070               # not needed to walk; documented
AVTAB_ENABLED_OLD = 0x80000000


class ParseError(Exception):
    pass


def _u32(b, off):
    return int.from_bytes(b[off:off + 4], "little")


class Policy:
    """Sequential walker over the binary policydb image."""

    def __init__(self, data):
        self.d = data
        self.n = len(data)
        self.off = 0
        self.sections = []          # (name, start, end, note)
        self.policyvers = None
        self.mls = None
        self.sym_nprim = [0] * SYM_NUM
        self.sym_nel = [0] * SYM_NUM
        self.policycaps = None
        self.permissive = None
        self.type_val_to_name = {}      # type value -> name (SYM_TYPES)

    # ---- low level -----------------------------------------------------
    def need(self, k):
        if k < 0 or self.off + k > self.n:
            raise ParseError(
                "truncated: need %d byte(s) at file offset 0x%x but only %d left"
                % (k, self.off, max(0, self.n - self.off)))

    def take(self, k):
        self.need(k)
        s = self.d[self.off:self.off + k]
        self.off += k
        return s

    def u8(self):
        self.need(1)
        v = self.d[self.off]
        self.off += 1
        return v

    def u16(self):
        self.need(2)
        v = int.from_bytes(self.d[self.off:self.off + 2], "little")
        self.off += 2
        return v

    def u32(self):
        self.need(4)
        v = int.from_bytes(self.d[self.off:self.off + 4], "little")
        self.off += 4
        return v

    def u64(self):
        self.need(8)
        v = int.from_bytes(self.d[self.off:self.off + 8], "little")
        self.off += 8
        return v

    def mark(self, name, start, note=""):
        self.sections.append((name, start, self.off, note))

    # ---- ebitmap -------------------------------------------------------
    def ebitmap_read(self, name=None, collect=False):
        start = self.off
        mapunit = self.u32()
        highbit_raw = self.u32()
        count = self.u32()
        if mapunit != BITS_PER_U64:
            raise ParseError(
                "ebitmap: mapunit=%d != 64 at 0x%x" % (mapunit, start))
        entries = []
        for _ in range(count):
            sb = self.u32()
            mp = self.u64()
            if sb % BITS_PER_U64:
                raise ParseError(
                    "ebitmap: startbit %d not a multiple of 64 at 0x%x"
                    % (sb, self.off - 12))
            entries.append((sb, mp))
        info = {
            "name": name, "offset": start, "end": self.off,
            "mapunit": mapunit, "highbit_raw": highbit_raw,
            "count": count, "entries": entries,
        }
        if name is not None:
            self.mark("ebitmap:" + name, start,
                      "mapunit=%d highbit=%d count=%d%s"
                      % (mapunit, highbit_raw, count,
                         (" " + ",".join("0x%x:0x%016x" % e for e in entries))
                         if entries else ""))
        if collect:
            info["bits"] = ebitmap_bits(entries)
        return info

    # ---- symtabs -------------------------------------------------------
    def perm_read(self):
        ln = self.u32()
        self.u32()                       # value
        self.take(ln)                    # key

    def read_cons_helper(self, ncons, allowxtarget):
        for _ in range(ncons):
            self.u32()                   # permissions
            nexpr = self.u32()
            for _ in range(nexpr):
                expr_type = self.u32()
                self.u32()               # attr
                self.u32()               # op
                if expr_type == CEXPR_NAMES:
                    self.ebitmap_read()  # names
                    if self.policyvers >= V_CONSTRAINT_NAMES:
                        self.type_set_read()

    def type_set_read(self):
        self.ebitmap_read()              # types
        self.ebitmap_read()              # negset
        self.u32()                       # flags

    def common_read(self):
        ln = self.u32()
        self.u32()                       # value
        self.u32()                       # nprim
        nel = self.u32()
        self.take(ln)
        for _ in range(nel):
            self.perm_read()

    def class_read(self):
        ln = self.u32()
        ln2 = self.u32()
        self.u32()                       # value
        self.u32()                       # nprim
        nel = self.u32()
        ncons = self.u32()
        self.take(ln)
        if ln2:
            self.take(ln2)
        for _ in range(nel):
            self.perm_read()
        self.read_cons_helper(ncons, False)
        if self.policyvers >= V_VALIDATETRANS:
            n2 = self.u32()
            self.read_cons_helper(n2, True)
        if self.policyvers >= V_NEW_OBJECT_DEFAULTS:
            self.u32(); self.u32(); self.u32()
        if self.policyvers >= V_DEFAULT_TYPE:
            self.u32()

    def role_read(self):
        to_read = 3 if self.policyvers >= V_BOUNDARY else 2
        ln = self.u32()
        for _ in range(to_read - 1):
            self.u32()                   # value, [bounds]
        self.take(ln)
        self.ebitmap_read()              # dominates
        self.ebitmap_read()              # types

    def type_read(self):
        to_read = 4 if self.policyvers >= V_BOUNDARY else 3
        ln = self.u32()
        value = self.u32()
        for _ in range(to_read - 2):
            self.u32()                   # prop, [bounds]
        self.type_val_to_name[value] = self.take(ln).decode("utf-8", "replace")

    def mls_range_read(self):
        items = self.u32()
        if items not in (1, 2):
            raise ParseError("mls range items=%d at 0x%x" % (items, self.off - 4))
        self.take(4 * items)             # sens[items]
        self.ebitmap_read()              # low cats
        if items > 1:
            self.ebitmap_read()          # high cats

    def mls_level_read(self):
        self.u32()                       # sens
        self.ebitmap_read()              # cats

    def user_read(self):
        to_read = 3 if self.policyvers >= V_BOUNDARY else 2
        ln = self.u32()
        for _ in range(to_read - 1):
            self.u32()                   # value, [bounds]
        self.take(ln)
        self.ebitmap_read()              # roles
        if self.policyvers >= V_MLS:
            self.mls_range_read()
            self.mls_level_read()

    def sens_read(self):
        ln = self.u32()
        self.u32()                       # isalias
        self.take(ln)
        self.mls_level_read()

    def cat_read(self):
        ln = self.u32()
        self.u32()                       # value
        self.u32()                       # isalias
        self.take(ln)

    def cond_read_bool(self):
        self.u32()                       # value
        self.u32()                       # state
        ln = self.u32()
        self.take(ln)

    READ_F = {0: common_read, 1: class_read, 2: role_read, 3: type_read,
              4: user_read, 5: cond_read_bool, 6: sens_read, 7: cat_read}

    def symtab_read(self, i):
        start = self.off
        nprim = self.u32()
        nel = self.u32()
        self.sym_nprim[i] = nprim
        self.sym_nel[i] = nel
        fn = self.READ_F[i]
        for _ in range(nel):
            fn(self)
        self.mark("symtab[%d]=%s" % (i, SYMTAB_NAMES[i]), start,
                  "nprim=%d nel=%d" % (nprim, nel))

    # ---- avtab ---------------------------------------------------------
    def avtab_read_item(self):
        if self.policyvers < V_AVTAB:
            items2 = self.u32()
            if items2 > 4:
                raise ParseError("avtab old entry overflow at 0x%x" % (self.off - 4))
            self.take(4 * items2)
            return
        self.u16()                       # source_type
        self.u16()                       # target_type
        self.u16()                       # target_class
        specified = self.u16()
        if specified & AVTAB_XPERMS:
            self.u8()                    # xperms.specified
            self.u8()                    # xperms.driver
            self.take(4 * 8)             # perms.p[8]
        else:
            self.u32()                   # datum

    def avtab_read(self, name):
        start = self.off
        nel = self.u32()
        for _ in range(nel):
            self.avtab_read_item()
        self.mark("avtab:" + name, start, "nel=%d" % nel)

    # ---- conditional list ---------------------------------------------
    def cond_read_av_list(self):
        ln = self.u32()
        for _ in range(ln):
            self.avtab_read_item()

    def cond_read_node(self):
        self.u32()                       # cur_state
        expr_len = self.u32()
        for _ in range(expr_len):
            self.u32(); self.u32()       # expr_type, bool
        self.cond_read_av_list()         # true_list
        self.cond_read_av_list()         # false_list

    def cond_read_list(self):
        start = self.off
        ln = self.u32()
        for _ in range(ln):
            self.cond_read_node()
        self.mark("cond_list", start, "nodes=%d" % ln)

    # ---- role trans / allow -------------------------------------------
    def role_trans_read(self):
        start = self.off
        nel = self.u32()
        for _ in range(nel):
            self.u32(); self.u32(); self.u32()
            if self.policyvers >= V_ROLETRANS:
                self.u32()
        self.mark("role_trans", start, "nel=%d" % nel)

    def role_allow_read(self):
        start = self.off
        nel = self.u32()
        for _ in range(nel):
            self.u32(); self.u32()
        self.mark("role_allow", start, "nel=%d" % nel)

    def filename_trans_read(self):
        if self.policyvers < V_FILENAME_TRANS:
            return
        start = self.off
        nel = self.u32()
        for _ in range(nel):
            ln = self.u32()
            self.take(ln)
            self.u32(); self.u32(); self.u32(); self.u32()
        self.mark("filename_trans", start, "nel=%d" % nel)

    # ---- ocontexts -----------------------------------------------------
    def context_read(self):
        self.u32(); self.u32(); self.u32()   # user, role, type
        if self.policyvers >= V_MLS:
            self.mls_range_read()

    def ocontext_read(self, ocon_num):
        for i in range(ocon_num):
            start = self.off
            nel = self.u32()
            for _ in range(nel):
                if i == OCON_ISID:
                    self.u32()                       # sid
                    self.context_read()
                elif i in (OCON_FS, OCON_NETIF):
                    ln = self.u32()
                    self.take(ln)
                    self.context_read(); self.context_read()
                elif i == OCON_PORT:
                    self.u32(); self.u32(); self.u32()
                    self.context_read()
                elif i == OCON_NODE:
                    self.u32(); self.u32()
                    self.context_read()
                elif i == OCON_FSUSE:
                    self.u32()                       # behavior
                    ln = self.u32()
                    self.take(ln)
                    self.context_read()
                elif i == OCON_NODE6:
                    self.take(4 * 8)
                    self.context_read()
                elif i == OCON_IBPKEY:
                    self.take(8)                     # subnet_prefix (be64)
                    self.u32(); self.u32()           # pkey lo/hi
                    self.context_read()
                elif i == OCON_IBENDPORT:
                    ln = self.u32()
                    self.u32()                       # port
                    self.take(ln)
                    self.context_read()
                else:
                    raise ParseError("unknown ocontext index %d" % i)
            self.mark("ocontext[%d]=%s" % (i, OCON_NAMES[i]), start,
                      "nel=%d" % nel)

    # ---- genfs ---------------------------------------------------------
    def genfs_read(self):
        start = self.off
        nel = self.u32()
        entries = 0
        for _ in range(nel):
            ln = self.u32()
            self.take(ln)                        # fstype
            nel2 = self.u32()
            entries += nel2
            for _ in range(nel2):
                ln = self.u32()
                self.take(ln)                    # name
                self.u32()                       # sclass
                self.context_read()
        self.mark("genfs", start, "fstypes=%d entries=%d" % (nel, entries))

    # ---- range trans ---------------------------------------------------
    def range_read(self):
        if self.policyvers < V_MLS:
            return
        start = self.off
        nel = self.u32()
        for _ in range(nel):
            self.u32(); self.u32()
            if self.policyvers >= V_RANGETRANS:
                self.u32()
            self.mls_range_read()
        self.mark("range_trans", start, "nel=%d" % nel)

    # ---- driver --------------------------------------------------------
    def lookup_compat(self, vers):
        best = None
        for v, s, o in COMPAT:
            if v <= vers:
                best = (s, o)
        return best

    def parse(self):
        hdr0 = self.off
        magic = self.u32()
        strlen = self.u32()
        if magic != MAGIC:
            raise ParseError("bad magic 0x%08x (want 0x%08x)" % (magic, MAGIC))
        s = self.take(strlen)
        if s != POLICYDB_STRING:
            raise ParseError("bad policydb string %r (want %r)"
                             % (s, POLICYDB_STRING))
        self.mark("magic+strlen+string", hdr0, "strlen=%d" % strlen)

        vert0 = self.off
        vers = self.u32()
        config = self.u32()
        sym_num = self.u32()
        ocon_num = self.u32()
        self.policyvers = vers
        self.mls = 1 if (config & 1) else 0
        self.mark("version+config+sym_num+ocon_num", vert0,
                  "policyvers=%d config=0x%x (MLS=%d) sym_num=%d ocon_num=%d"
                  % (vers, config, self.mls, sym_num, ocon_num))
        if not (V_MIN <= vers <= V_MAX):
            raise ParseError("policyvers %d outside %d..%d" % (vers, V_MIN, V_MAX))
        comp = self.lookup_compat(vers)
        if comp is None:
            raise ParseError("no compat entry for policyvers %d" % vers)
        if (sym_num, ocon_num) != comp:
            raise ParseError(
                "table sizes (%d,%d) != compat (%d,%d) for version %d"
                % (sym_num, ocon_num, comp[0], comp[1], vers))

        if vers >= V_POLCAP:
            self.policycaps = self.ebitmap_read("policycaps", collect=True)
        if vers >= V_PERMISSIVE:
            self.permissive = self.ebitmap_read("permissive_map", collect=True)

        for i in range(sym_num):
            self.symtab_read(i)

        self.avtab_read("te_avtab")
        if vers >= V_BOOL:
            self.cond_read_list()
        self.role_trans_read()
        self.role_allow_read()
        self.filename_trans_read()
        self.ocontext_read(ocon_num)
        self.genfs_read()
        self.range_read()

        # type_attr_map: p_types.nprim ebitmaps
        tat0 = self.off
        nprim_types = self.sym_nprim[SYM_TYPES]
        if vers >= V_AVTAB:
            for _ in range(nprim_types):
                self.ebitmap_read()
        self.mark("type_attr_map", tat0, "ebitmaps=%d" % nprim_types)

        if self.off != self.n:
            raise ParseError(
                "walk ended at 0x%x but file is 0x%x bytes (%d trailing byte(s))"
                % (self.off, self.n, self.n - self.off))
        return self


# ---------------------------------------------------------------------------
# ebitmap helpers
# ---------------------------------------------------------------------------
def ebitmap_bits(entries):
    bits = set()
    for sb, mp in entries:
        k = 0
        while mp:
            if mp & 1:
                bits.add(sb + k)
            mp >>= 1
            k += 1
    return bits


def roundup(x, m):
    return ((x + m - 1) // m) * m


def ebitmap_encode(bits):
    """Encode a set of bit positions exactly as ss/ebitmap.c ebitmap_write()."""
    bits = sorted(b for b in bits if b >= 0)
    if not bits:
        return (64).to_bytes(4, "little") + (0).to_bytes(4, "little") \
            + (0).to_bytes(4, "little")
    words = {}                       # startbit(64-aligned) -> u64 map
    for b in bits:
        sb = (b // BITS_PER_U64) * BITS_PER_U64
        words[sb] = words.get(sb, 0) | (1 << (b - sb))
    last_bit = roundup(bits[-1] + 1, BITS_PER_U64)
    out = bytearray()
    out += (BITS_PER_U64).to_bytes(4, "little")
    out += last_bit.to_bytes(4, "little")
    out += len(words).to_bytes(4, "little")
    for sb in sorted(words):
        out += sb.to_bytes(4, "little")
        out += (words[sb] & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    return bytes(out)


def fmt_sections(p):
    lines = []
    for name, start, end, note in p.sections:
        lines.append("  0x%08x .. 0x%08x  (%8d)  %-38s %s"
                     % (start, max(start, end - 1) if end > start else start,
                        end - start, name, note))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# patch
# ---------------------------------------------------------------------------
def patch_permissive(data, target):
    p = Policy(data).parse()
    if p.permissive is None:
        raise ParseError("policy version %d has no permissive_map" % p.policyvers)
    old_off = p.permissive["offset"]
    old_end = p.permissive["end"]
    old_bits = p.permissive["bits"]
    new_bits = set(old_bits)
    new_bits.add(target)
    new_enc = ebitmap_encode(new_bits)
    out = data[:old_off] + new_enc + data[old_end:]
    info = {
        "old_offset": old_off,
        "old_end": old_end,
        "old_len": old_end - old_off,
        "old_bits": old_bits,
        "new_bits": new_bits,
        "new_enc": new_enc,
        "delta": len(new_enc) - (old_end - old_off),
        "already": target in old_bits,
    }
    return out, info, p


def verify(out_data, target, expect_end):
    p = Policy(out_data).parse()
    bits = p.permissive["bits"] if p.permissive else set()
    return {
        "bit_set": target in bits,
        "perms": bits,
        "pmap_offset": p.permissive["offset"] if p.permissive else None,
        "pmap_end": p.permissive["end"] if p.permissive else None,
        "walk_end": p.off,
        "file_len": len(out_data),
        "end_ok": p.off == expect_end,
    }


def main(argv):
    args = [a for a in argv[1:]]
    target = 1153
    positional = []
    for a in args:
        if a in ("-h", "--help"):
            print(__doc__)
            return 0
        try:
            # a bare integer is the type value (only accept after 2 positionals)
            if len(positional) >= 2 and a.lstrip("-").isdigit():
                target = int(a)
                continue
        except ValueError:
            pass
        positional.append(a)

    if len(positional) < 1:
        print(__doc__)
        return 2

    path_in = positional[0]
    with open(path_in, "rb") as f:
        data = f.read()

    print("== input ==")
    print("file    : %s" % path_in)
    print("size    : %d (0x%x)" % (len(data), len(data)))

    p = Policy(data).parse()
    print("policyvers : %d (0x%x)" % (p.policyvers, p.policyvers))
    print("config     : MLS=%d" % p.mls)
    print("sections   :")
    print(fmt_sections(p))

    pm = p.permissive
    print()
    print("permissive_map offset : 0x%x (%d)" % (pm["offset"], pm["offset"]))
    print("permissive_map end    : 0x%x" % pm["end"])
    print("encoding              : mapunit=%d highbit=%d count=%d"
          % (pm["mapunit"], pm["highbit_raw"], pm["count"]))
    print("current permissive set: %s" % (sorted(pm["bits"]) or "(empty)"))

    tname = p.type_val_to_name.get(target)
    print("target type value     : %d%s"
          % (target, (" (%s)" % tname) if tname else " (no such type in symtab)"))

    policycaps_bits = sorted(p.policycaps["bits"]) if p.policycaps else []
    print("policycaps bits       : %s" % (policycaps_bits or "(empty)"))

    if len(positional) < 2:
        print("\n(no output file given; parse-only)")
        return 0

    path_out = positional[1]
    out, info, _ = patch_permissive(data, target)

    print()
    print("== patch ==")
    print("target type value     : %d%s"
          % (target, (" (%s)" % tname) if tname else ""))
    print("already permissive    : %s" % info["already"])
    print("old map bytes (len %d): %s"
          % (info["old_len"], data[info["old_offset"]:info["old_end"]].hex(" ")))
    print("new map bytes (len %d): %s" % (len(info["new_enc"]), info["new_enc"].hex(" ")))
    print("size delta            : %+d" % info["delta"])
    print("new permissive set    : %s" % sorted(info["new_bits"]))

    with open(path_out, "wb") as f:
        f.write(out)
    print("wrote %s (%d bytes)" % (path_out, len(out)))

    print()
    print("== verify (re-parse %s) ==" % path_out)
    v = verify(out, target, p.n + info["delta"])
    print("bit %d set            : %s" % (target, v["bit_set"]))
    print("re-parsed permissive   : %s" % sorted(v["perms"]))
    print("permissive_map offset  : 0x%x" % v["pmap_offset"])
    print("walk consumed file     : %s (%d of %d bytes)"
          % (v["end_ok"], v["walk_end"], v["file_len"]))
    if not (v["bit_set"] and v["end_ok"]):
        print("VERIFY FAILED")
        return 1
    print("VERIFY OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except ParseError as e:
        sys.stderr.write("PARSE ERROR: %s\n" % e)
        sys.exit(3)
