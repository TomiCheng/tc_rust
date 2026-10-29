//! 移植自 zlib 1.3.2 的 `trees.c`／`trees.h`：Huffman 樹的建構與區塊輸出。

use crate::constants::Strategy;

pub(super) const LENGTH_CODES: usize = 29;
pub(super) const LITERALS: usize = 256;
pub(super) const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
pub(super) const D_CODES: usize = 30;
const BL_CODES: usize = 19;
pub(super) const HEAP_SIZE: usize = 2 * L_CODES + 1;
const MAX_BITS: usize = 15;
const MAX_BL_BITS: usize = 7;
const BUF_SIZE: i32 = 16;
const END_BLOCK: usize = 256;
const REP_3_6: usize = 16;
const REPZ_3_10: usize = 17;
const REPZ_11_138: usize = 18;
const STORED_BLOCK: u32 = 0;
const STATIC_TREES: u32 = 1;
const DYN_TREES: u32 = 2;

const EXTRA_LBITS: [u32; LENGTH_CODES] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const EXTRA_DBITS: [u32; D_CODES] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const EXTRA_BLBITS: [u32; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];
const BL_ORDER: [usize; BL_CODES] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// C 的 `ct_data`：兩個 union 照原樣保留，`fc` 是 Freq／Code，`dl` 是 Dad／Len。
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct CtData {
    fc: u16,
    dl: u16,
}

const fn ct(code: u16, len: u16) -> CtData {
    CtData { fc: code, dl: len }
}

struct StaticTreeDesc {
    static_tree: Option<&'static [CtData]>,
    extra_bits: &'static [u32],
    extra_base: usize,
    elems: usize,
    max_length: u32,
}

static STATIC_L_DESC: StaticTreeDesc = StaticTreeDesc {
    static_tree: Some(&STATIC_LTREE),
    extra_bits: &EXTRA_LBITS,
    extra_base: LITERALS + 1,
    elems: L_CODES,
    max_length: MAX_BITS as u32,
};
static STATIC_D_DESC: StaticTreeDesc = StaticTreeDesc {
    static_tree: Some(&STATIC_DTREE),
    extra_bits: &EXTRA_DBITS,
    extra_base: 0,
    elems: D_CODES,
    max_length: MAX_BITS as u32,
};
static STATIC_BL_DESC: StaticTreeDesc = StaticTreeDesc {
    static_tree: None,
    extra_bits: &EXTRA_BLBITS,
    extra_base: 0,
    elems: BL_CODES,
    max_length: MAX_BL_BITS as u32,
};

#[derive(Clone, Copy)]
enum Kind {
    L,
    D,
    Bl,
}

impl Kind {
    fn desc(self) -> &'static StaticTreeDesc {
        match self {
            Kind::L => &STATIC_L_DESC,
            Kind::D => &STATIC_D_DESC,
            Kind::Bl => &STATIC_BL_DESC,
        }
    }
}

pub(super) fn d_code(dist: usize) -> usize {
    if dist < 256 {
        usize::from(DIST_CODE[dist])
    } else {
        usize::from(DIST_CODE[256 + (dist >> 7)])
    }
}

fn bi_reverse(mut code: u32, mut len: u32) -> u32 {
    let mut res = 0;
    loop {
        res |= code & 1;
        code >>= 1;
        res <<= 1;
        len -= 1;
        if len == 0 {
            break;
        }
    }
    res >> 1
}

/// `pending_buf` 與位元累加器。C 把 `sym_buf` 疊在 `pending_buf` 裡；這裡分開放，
/// 輸出不變。
pub(super) struct Bits {
    pub(super) pending_buf: Vec<u8>,
    pub(super) pending_buf_size: usize,
    pub(super) pending_out: usize,
    pub(super) pending: usize,
    pub(super) bi_buf: u16,
    pub(super) bi_valid: i32,
}

impl Bits {
    pub(super) fn new(pending_buf_size: usize) -> Self {
        Self {
            pending_buf: vec![0; pending_buf_size],
            pending_buf_size,
            pending_out: 0,
            pending: 0,
            bi_buf: 0,
            bi_valid: 0,
        }
    }

    pub(super) fn put_byte(&mut self, c: u8) {
        self.pending_buf[self.pending_out + self.pending] = c;
        self.pending += 1;
    }

    fn put_short(&mut self, w: u16) {
        self.put_byte(w as u8);
        self.put_byte((w >> 8) as u8);
    }

    pub(super) fn put_short_msb(&mut self, b: u32) {
        self.put_byte((b >> 8) as u8);
        self.put_byte(b as u8);
    }

    fn send_bits(&mut self, value: u32, length: u32) {
        let len = length as i32;
        if self.bi_valid > BUF_SIZE - len {
            let val = value as u16;
            self.bi_buf |= (u32::from(val) << self.bi_valid) as u16;
            self.put_short(self.bi_buf);
            self.bi_buf = val >> (BUF_SIZE - self.bi_valid);
            self.bi_valid += len - BUF_SIZE;
        } else {
            self.bi_buf |= ((value & 0xffff) << self.bi_valid) as u16;
            self.bi_valid += len;
        }
    }

    fn send_code(&mut self, c: usize, tree: &[CtData]) {
        self.send_bits(u32::from(tree[c].fc), u32::from(tree[c].dl));
    }

    pub(super) fn bi_flush(&mut self) {
        if self.bi_valid == 16 {
            self.put_short(self.bi_buf);
            self.bi_buf = 0;
            self.bi_valid = 0;
        } else if self.bi_valid >= 8 {
            self.put_byte(self.bi_buf as u8);
            self.bi_buf >>= 8;
            self.bi_valid -= 8;
        }
    }

    fn bi_windup(&mut self) {
        if self.bi_valid > 8 {
            self.put_short(self.bi_buf);
        } else if self.bi_valid > 0 {
            self.put_byte(self.bi_buf as u8);
        }
        self.bi_buf = 0;
        self.bi_valid = 0;
    }

    /// `_tr_stored_block()`；`buf` 為空時只寫區塊頭，C 傳 `NULL, 0` 的情形。
    pub(super) fn tr_stored_block(&mut self, buf: &[u8], last: bool) {
        self.send_bits((STORED_BLOCK << 1) + u32::from(last), 3);
        self.bi_windup();
        self.put_short(buf.len() as u16);
        self.put_short(!(buf.len() as u16));
        let at = self.pending_out + self.pending;
        self.pending_buf[at..at + buf.len()].copy_from_slice(buf);
        self.pending += buf.len();
    }
}

fn smaller(tree: &[CtData], n: usize, m: usize, depth: &[u8]) -> bool {
    tree[n].fc < tree[m].fc || (tree[n].fc == tree[m].fc && depth[n] <= depth[m])
}

fn pqdownheap(heap: &mut [usize], heap_len: usize, depth: &[u8], tree: &[CtData], mut k: usize) {
    let v = heap[k];
    let mut j = k << 1;
    while j <= heap_len {
        if j < heap_len && smaller(tree, heap[j + 1], heap[j], depth) {
            j += 1;
        }
        if smaller(tree, v, heap[j], depth) {
            break;
        }
        heap[k] = heap[j];
        k = j;
        j <<= 1;
    }
    heap[k] = v;
}

#[allow(clippy::too_many_arguments)]
fn gen_bitlen(
    tree: &mut [CtData],
    max_code: usize,
    desc: &StaticTreeDesc,
    heap: &[usize],
    heap_max: usize,
    bl_count: &mut [u16; MAX_BITS + 1],
    opt_len: &mut u64,
    static_len: &mut u64,
) {
    let max_length = desc.max_length;
    bl_count.fill(0);

    tree[heap[heap_max]].dl = 0;
    let mut overflow = 0i32;
    for &n in &heap[heap_max + 1..HEAP_SIZE] {
        let mut bits = u32::from(tree[usize::from(tree[n].dl)].dl) + 1;
        if bits > max_length {
            bits = max_length;
            overflow += 1;
        }
        tree[n].dl = bits as u16;
        if n > max_code {
            continue;
        }
        bl_count[bits as usize] += 1;
        let xbits = if n >= desc.extra_base {
            desc.extra_bits[n - desc.extra_base]
        } else {
            0
        };
        let f = u64::from(tree[n].fc);
        *opt_len = opt_len.wrapping_add(f * u64::from(bits + xbits));
        if let Some(stree) = desc.static_tree {
            *static_len = static_len.wrapping_add(f * u64::from(u32::from(stree[n].dl) + xbits));
        }
    }
    if overflow == 0 {
        return;
    }

    loop {
        let mut bits = max_length as usize - 1;
        while bl_count[bits] == 0 {
            bits -= 1;
        }
        bl_count[bits] -= 1;
        bl_count[bits + 1] += 2;
        bl_count[max_length as usize] -= 1;
        overflow -= 2;
        if overflow <= 0 {
            break;
        }
    }

    let mut h = HEAP_SIZE;
    for bits in (1..=max_length as usize).rev() {
        let mut n = bl_count[bits];
        while n != 0 {
            h -= 1;
            let m = heap[h];
            if m > max_code {
                continue;
            }
            if usize::from(tree[m].dl) != bits {
                let delta = (bits as u64).wrapping_sub(u64::from(tree[m].dl));
                *opt_len = opt_len.wrapping_add(delta.wrapping_mul(u64::from(tree[m].fc)));
                tree[m].dl = bits as u16;
            }
            n -= 1;
        }
    }
}

fn gen_codes(tree: &mut [CtData], max_code: usize, bl_count: &[u16; MAX_BITS + 1]) {
    let mut next_code = [0u16; MAX_BITS + 1];
    let mut code = 0u32;
    for bits in 1..=MAX_BITS {
        code = (code + u32::from(bl_count[bits - 1])) << 1;
        next_code[bits] = code as u16;
    }
    for node in &mut tree[..=max_code] {
        let len = usize::from(node.dl);
        if len == 0 {
            continue;
        }
        node.fc = bi_reverse(u32::from(next_code[len]), len as u32) as u16;
        next_code[len] = next_code[len].wrapping_add(1);
    }
}

fn compress_block(bits: &mut Bits, sym_buf: &[u8], ltree: &[CtData], dtree: &[CtData]) {
    for sym in sym_buf.chunks_exact(3) {
        let mut dist = usize::from(sym[0]) + (usize::from(sym[1]) << 8);
        let mut lc = usize::from(sym[2]);
        if dist == 0 {
            bits.send_code(lc, ltree);
        } else {
            let code = usize::from(LENGTH_CODE[lc]);
            bits.send_code(code + LITERALS + 1, ltree);
            let extra = EXTRA_LBITS[code];
            if extra != 0 {
                lc -= BASE_LENGTH[code] as usize;
                bits.send_bits(lc as u32, extra);
            }
            dist -= 1;
            let code = d_code(dist);
            bits.send_code(code, dtree);
            let extra = EXTRA_DBITS[code];
            if extra != 0 {
                dist -= BASE_DIST[code] as usize;
                bits.send_bits(dist as u32, extra);
            }
        }
    }
    bits.send_code(END_BLOCK, ltree);
}

pub(super) struct Trees {
    dyn_ltree: [CtData; HEAP_SIZE],
    dyn_dtree: [CtData; 2 * D_CODES + 1],
    bl_tree: [CtData; 2 * BL_CODES + 1],
    l_max_code: usize,
    d_max_code: usize,
    bl_count: [u16; MAX_BITS + 1],
    heap: [usize; 2 * L_CODES + 1],
    heap_len: usize,
    heap_max: usize,
    depth: [u8; 2 * L_CODES + 1],
    sym_buf: Vec<u8>,
    pub(super) sym_next: usize,
    sym_end: usize,
    opt_len: u64,
    static_len: u64,
    pub(super) matches: u32,
}

impl Trees {
    /// `_tr_init()`：`lit_bufsize` 個符號的緩衝區，滿 `lit_bufsize - 1` 個就送出區塊。
    pub(super) fn new(lit_bufsize: usize) -> Self {
        let mut trees = Self {
            dyn_ltree: [CtData::default(); HEAP_SIZE],
            dyn_dtree: [CtData::default(); 2 * D_CODES + 1],
            bl_tree: [CtData::default(); 2 * BL_CODES + 1],
            l_max_code: 0,
            d_max_code: 0,
            bl_count: [0; MAX_BITS + 1],
            heap: [0; 2 * L_CODES + 1],
            heap_len: 0,
            heap_max: 0,
            depth: [0; 2 * L_CODES + 1],
            sym_buf: vec![0; lit_bufsize * 3],
            sym_next: 0,
            sym_end: (lit_bufsize - 1) * 3,
            opt_len: 0,
            static_len: 0,
            matches: 0,
        };
        trees.init_block();
        trees
    }

    fn init_block(&mut self) {
        for n in &mut self.dyn_ltree[..L_CODES] {
            n.fc = 0;
        }
        for n in &mut self.dyn_dtree[..D_CODES] {
            n.fc = 0;
        }
        for n in &mut self.bl_tree[..BL_CODES] {
            n.fc = 0;
        }
        self.dyn_ltree[END_BLOCK].fc = 1;
        self.opt_len = 0;
        self.static_len = 0;
        self.sym_next = 0;
        self.matches = 0;
    }

    /// `_tr_tally()`：記下一個字面值（`dist == 0`）或一組比對；回傳是否該送出區塊。
    pub(super) fn tally(&mut self, dist: usize, lc: usize) -> bool {
        self.sym_buf[self.sym_next] = dist as u8;
        self.sym_buf[self.sym_next + 1] = (dist >> 8) as u8;
        self.sym_buf[self.sym_next + 2] = lc as u8;
        self.sym_next += 3;
        if dist == 0 {
            self.dyn_ltree[lc].fc += 1;
        } else {
            self.matches += 1;
            let dist = dist - 1;
            self.dyn_ltree[usize::from(LENGTH_CODE[lc]) + LITERALS + 1].fc += 1;
            self.dyn_dtree[d_code(dist)].fc += 1;
        }
        self.sym_next == self.sym_end
    }

    fn build_tree(&mut self, kind: Kind) {
        let desc = kind.desc();
        let tree: &mut [CtData] = match kind {
            Kind::L => &mut self.dyn_ltree,
            Kind::D => &mut self.dyn_dtree,
            Kind::Bl => &mut self.bl_tree,
        };
        let elems = desc.elems;
        let mut max_code: isize = -1;

        self.heap_len = 0;
        self.heap_max = HEAP_SIZE;
        for (n, node) in tree[..elems].iter_mut().enumerate() {
            if node.fc != 0 {
                self.heap_len += 1;
                self.heap[self.heap_len] = n;
                max_code = n as isize;
                self.depth[n] = 0;
            } else {
                node.dl = 0;
            }
        }

        while self.heap_len < 2 {
            let node = if max_code < 2 {
                max_code += 1;
                max_code as usize
            } else {
                0
            };
            self.heap_len += 1;
            self.heap[self.heap_len] = node;
            tree[node].fc = 1;
            self.depth[node] = 0;
            self.opt_len = self.opt_len.wrapping_sub(1);
            if let Some(stree) = desc.static_tree {
                self.static_len = self.static_len.wrapping_sub(u64::from(stree[node].dl));
            }
        }
        let max_code = max_code as usize;

        for n in (1..=self.heap_len / 2).rev() {
            pqdownheap(&mut self.heap, self.heap_len, &self.depth, tree, n);
        }

        let mut node = elems;
        loop {
            let n = self.heap[1];
            self.heap[1] = self.heap[self.heap_len];
            self.heap_len -= 1;
            pqdownheap(&mut self.heap, self.heap_len, &self.depth, tree, 1);
            let m = self.heap[1];

            self.heap_max -= 1;
            self.heap[self.heap_max] = n;
            self.heap_max -= 1;
            self.heap[self.heap_max] = m;

            tree[node].fc = tree[n].fc.wrapping_add(tree[m].fc);
            self.depth[node] = self.depth[n].max(self.depth[m]) + 1;
            tree[n].dl = node as u16;
            tree[m].dl = node as u16;

            self.heap[1] = node;
            node += 1;
            pqdownheap(&mut self.heap, self.heap_len, &self.depth, tree, 1);
            if self.heap_len < 2 {
                break;
            }
        }
        self.heap_max -= 1;
        self.heap[self.heap_max] = self.heap[1];

        gen_bitlen(
            tree,
            max_code,
            desc,
            &self.heap,
            self.heap_max,
            &mut self.bl_count,
            &mut self.opt_len,
            &mut self.static_len,
        );
        gen_codes(tree, max_code, &self.bl_count);

        match kind {
            Kind::L => self.l_max_code = max_code,
            Kind::D => self.d_max_code = max_code,
            Kind::Bl => {}
        }
    }

    fn scan_tree(&mut self, kind: Kind, max_code: usize) {
        let tree: &mut [CtData] = match kind {
            Kind::L => &mut self.dyn_ltree,
            _ => &mut self.dyn_dtree,
        };
        let mut prevlen: i32 = -1;
        let mut nextlen = i32::from(tree[0].dl);
        let mut count = 0u16;
        let (mut max_count, mut min_count) = if nextlen == 0 { (138, 3) } else { (7, 4) };

        tree[max_code + 1].dl = 0xffff;
        for n in 0..=max_code {
            let curlen = nextlen;
            nextlen = i32::from(tree[n + 1].dl);
            count += 1;
            if count < max_count && curlen == nextlen {
                continue;
            } else if count < min_count {
                self.bl_tree[curlen as usize].fc += count;
            } else if curlen != 0 {
                if curlen != prevlen {
                    self.bl_tree[curlen as usize].fc += 1;
                }
                self.bl_tree[REP_3_6].fc += 1;
            } else if count <= 10 {
                self.bl_tree[REPZ_3_10].fc += 1;
            } else {
                self.bl_tree[REPZ_11_138].fc += 1;
            }
            count = 0;
            prevlen = curlen;
            (max_count, min_count) = if nextlen == 0 {
                (138, 3)
            } else if curlen == nextlen {
                (6, 3)
            } else {
                (7, 4)
            };
        }
    }

    fn send_tree(&self, bits: &mut Bits, kind: Kind, max_code: usize) {
        let tree: &[CtData] = match kind {
            Kind::L => &self.dyn_ltree,
            _ => &self.dyn_dtree,
        };
        let bl_tree = &self.bl_tree;
        let mut prevlen: i32 = -1;
        let mut nextlen = i32::from(tree[0].dl);
        let mut count = 0u32;
        let (mut max_count, mut min_count) = if nextlen == 0 { (138, 3) } else { (7, 4) };

        for n in 0..=max_code {
            let curlen = nextlen;
            nextlen = i32::from(tree[n + 1].dl);
            count += 1;
            if count < max_count && curlen == nextlen {
                continue;
            } else if count < min_count {
                loop {
                    bits.send_code(curlen as usize, bl_tree);
                    count -= 1;
                    if count == 0 {
                        break;
                    }
                }
            } else if curlen != 0 {
                if curlen != prevlen {
                    bits.send_code(curlen as usize, bl_tree);
                    count -= 1;
                }
                bits.send_code(REP_3_6, bl_tree);
                bits.send_bits(count - 3, 2);
            } else if count <= 10 {
                bits.send_code(REPZ_3_10, bl_tree);
                bits.send_bits(count - 3, 3);
            } else {
                bits.send_code(REPZ_11_138, bl_tree);
                bits.send_bits(count - 11, 7);
            }
            count = 0;
            prevlen = curlen;
            (max_count, min_count) = if nextlen == 0 {
                (138, 3)
            } else if curlen == nextlen {
                (6, 3)
            } else {
                (7, 4)
            };
        }
    }

    fn build_bl_tree(&mut self) -> usize {
        self.scan_tree(Kind::L, self.l_max_code);
        self.scan_tree(Kind::D, self.d_max_code);
        self.build_tree(Kind::Bl);

        let mut max_blindex = BL_CODES - 1;
        while max_blindex >= 3 {
            if self.bl_tree[BL_ORDER[max_blindex]].dl != 0 {
                break;
            }
            max_blindex -= 1;
        }
        self.opt_len = self
            .opt_len
            .wrapping_add(3 * (max_blindex as u64 + 1) + 5 + 5 + 4);
        max_blindex
    }

    fn send_all_trees(&self, bits: &mut Bits, lcodes: usize, dcodes: usize, blcodes: usize) {
        bits.send_bits(lcodes as u32 - 257, 5);
        bits.send_bits(dcodes as u32 - 1, 5);
        bits.send_bits(blcodes as u32 - 4, 4);
        for &order in &BL_ORDER[..blcodes] {
            bits.send_bits(u32::from(self.bl_tree[order].dl), 3);
        }
        self.send_tree(bits, Kind::L, lcodes - 1);
        self.send_tree(bits, Kind::D, dcodes - 1);
    }

    /// `_tr_flush_block()`：選 stored、固定或動態編碼送出目前的區塊。`buf` 是區塊在
    /// 視窗裡的原始資料；C 的 `block_start < 0` 對應 `None`。
    pub(super) fn flush_block(
        &mut self,
        bits: &mut Bits,
        buf: Option<&[u8]>,
        stored_len: usize,
        last: bool,
        level: u32,
        strategy: Strategy,
    ) {
        let mut max_blindex = 0;
        let (opt_lenb, static_lenb);
        if level > 0 {
            self.build_tree(Kind::L);
            self.build_tree(Kind::D);
            max_blindex = self.build_bl_tree();

            let mut opt = self.opt_len.wrapping_add(3 + 7) >> 3;
            let stat = self.static_len.wrapping_add(3 + 7) >> 3;
            if stat <= opt || strategy == Strategy::Fixed {
                opt = stat;
            }
            opt_lenb = opt;
            static_lenb = stat;
        } else {
            opt_lenb = stored_len as u64 + 5;
            static_lenb = opt_lenb;
        }

        let sym_buf = &self.sym_buf[..self.sym_next];
        match buf {
            Some(buf) if stored_len as u64 + 4 <= opt_lenb => bits.tr_stored_block(buf, last),
            _ if static_lenb == opt_lenb => {
                bits.send_bits((STATIC_TREES << 1) + u32::from(last), 3);
                compress_block(bits, sym_buf, &STATIC_LTREE, &STATIC_DTREE);
            }
            _ => {
                bits.send_bits((DYN_TREES << 1) + u32::from(last), 3);
                self.send_all_trees(
                    bits,
                    self.l_max_code + 1,
                    self.d_max_code + 1,
                    max_blindex + 1,
                );
                compress_block(bits, sym_buf, &self.dyn_ltree, &self.dyn_dtree);
            }
        }

        self.init_block();
        if last {
            bits.bi_windup();
        }
    }
}

#[rustfmt::skip]
pub(super) const STATIC_LTREE: [CtData; 288] = [
    ct(12, 8), ct(140, 8), ct(76, 8), ct(204, 8), ct(44, 8), ct(172, 8), ct(108, 8), ct(236, 8),
    ct(28, 8), ct(156, 8), ct(92, 8), ct(220, 8), ct(60, 8), ct(188, 8), ct(124, 8), ct(252, 8),
    ct(2, 8), ct(130, 8), ct(66, 8), ct(194, 8), ct(34, 8), ct(162, 8), ct(98, 8), ct(226, 8),
    ct(18, 8), ct(146, 8), ct(82, 8), ct(210, 8), ct(50, 8), ct(178, 8), ct(114, 8), ct(242, 8),
    ct(10, 8), ct(138, 8), ct(74, 8), ct(202, 8), ct(42, 8), ct(170, 8), ct(106, 8), ct(234, 8),
    ct(26, 8), ct(154, 8), ct(90, 8), ct(218, 8), ct(58, 8), ct(186, 8), ct(122, 8), ct(250, 8),
    ct(6, 8), ct(134, 8), ct(70, 8), ct(198, 8), ct(38, 8), ct(166, 8), ct(102, 8), ct(230, 8),
    ct(22, 8), ct(150, 8), ct(86, 8), ct(214, 8), ct(54, 8), ct(182, 8), ct(118, 8), ct(246, 8),
    ct(14, 8), ct(142, 8), ct(78, 8), ct(206, 8), ct(46, 8), ct(174, 8), ct(110, 8), ct(238, 8),
    ct(30, 8), ct(158, 8), ct(94, 8), ct(222, 8), ct(62, 8), ct(190, 8), ct(126, 8), ct(254, 8),
    ct(1, 8), ct(129, 8), ct(65, 8), ct(193, 8), ct(33, 8), ct(161, 8), ct(97, 8), ct(225, 8),
    ct(17, 8), ct(145, 8), ct(81, 8), ct(209, 8), ct(49, 8), ct(177, 8), ct(113, 8), ct(241, 8),
    ct(9, 8), ct(137, 8), ct(73, 8), ct(201, 8), ct(41, 8), ct(169, 8), ct(105, 8), ct(233, 8),
    ct(25, 8), ct(153, 8), ct(89, 8), ct(217, 8), ct(57, 8), ct(185, 8), ct(121, 8), ct(249, 8),
    ct(5, 8), ct(133, 8), ct(69, 8), ct(197, 8), ct(37, 8), ct(165, 8), ct(101, 8), ct(229, 8),
    ct(21, 8), ct(149, 8), ct(85, 8), ct(213, 8), ct(53, 8), ct(181, 8), ct(117, 8), ct(245, 8),
    ct(13, 8), ct(141, 8), ct(77, 8), ct(205, 8), ct(45, 8), ct(173, 8), ct(109, 8), ct(237, 8),
    ct(29, 8), ct(157, 8), ct(93, 8), ct(221, 8), ct(61, 8), ct(189, 8), ct(125, 8), ct(253, 8),
    ct(19, 9), ct(275, 9), ct(147, 9), ct(403, 9), ct(83, 9), ct(339, 9), ct(211, 9), ct(467, 9),
    ct(51, 9), ct(307, 9), ct(179, 9), ct(435, 9), ct(115, 9), ct(371, 9), ct(243, 9), ct(499, 9),
    ct(11, 9), ct(267, 9), ct(139, 9), ct(395, 9), ct(75, 9), ct(331, 9), ct(203, 9), ct(459, 9),
    ct(43, 9), ct(299, 9), ct(171, 9), ct(427, 9), ct(107, 9), ct(363, 9), ct(235, 9), ct(491, 9),
    ct(27, 9), ct(283, 9), ct(155, 9), ct(411, 9), ct(91, 9), ct(347, 9), ct(219, 9), ct(475, 9),
    ct(59, 9), ct(315, 9), ct(187, 9), ct(443, 9), ct(123, 9), ct(379, 9), ct(251, 9), ct(507, 9),
    ct(7, 9), ct(263, 9), ct(135, 9), ct(391, 9), ct(71, 9), ct(327, 9), ct(199, 9), ct(455, 9),
    ct(39, 9), ct(295, 9), ct(167, 9), ct(423, 9), ct(103, 9), ct(359, 9), ct(231, 9), ct(487, 9),
    ct(23, 9), ct(279, 9), ct(151, 9), ct(407, 9), ct(87, 9), ct(343, 9), ct(215, 9), ct(471, 9),
    ct(55, 9), ct(311, 9), ct(183, 9), ct(439, 9), ct(119, 9), ct(375, 9), ct(247, 9), ct(503, 9),
    ct(15, 9), ct(271, 9), ct(143, 9), ct(399, 9), ct(79, 9), ct(335, 9), ct(207, 9), ct(463, 9),
    ct(47, 9), ct(303, 9), ct(175, 9), ct(431, 9), ct(111, 9), ct(367, 9), ct(239, 9), ct(495, 9),
    ct(31, 9), ct(287, 9), ct(159, 9), ct(415, 9), ct(95, 9), ct(351, 9), ct(223, 9), ct(479, 9),
    ct(63, 9), ct(319, 9), ct(191, 9), ct(447, 9), ct(127, 9), ct(383, 9), ct(255, 9), ct(511, 9),
    ct(0, 7), ct(64, 7), ct(32, 7), ct(96, 7), ct(16, 7), ct(80, 7), ct(48, 7), ct(112, 7),
    ct(8, 7), ct(72, 7), ct(40, 7), ct(104, 7), ct(24, 7), ct(88, 7), ct(56, 7), ct(120, 7),
    ct(4, 7), ct(68, 7), ct(36, 7), ct(100, 7), ct(20, 7), ct(84, 7), ct(52, 7), ct(116, 7),
    ct(3, 8), ct(131, 8), ct(67, 8), ct(195, 8), ct(35, 8), ct(163, 8), ct(99, 8), ct(227, 8),
];

#[rustfmt::skip]
pub(super) const STATIC_DTREE: [CtData; 30] = [
    ct(0, 5), ct(16, 5), ct(8, 5), ct(24, 5), ct(4, 5), ct(20, 5), ct(12, 5), ct(28, 5),
    ct(2, 5), ct(18, 5), ct(10, 5), ct(26, 5), ct(6, 5), ct(22, 5), ct(14, 5), ct(30, 5),
    ct(1, 5), ct(17, 5), ct(9, 5), ct(25, 5), ct(5, 5), ct(21, 5), ct(13, 5), ct(29, 5),
    ct(3, 5), ct(19, 5), ct(11, 5), ct(27, 5), ct(7, 5), ct(23, 5),
];

#[rustfmt::skip]
pub(super) const DIST_CODE: [u8; 512] = [
    0, 1, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8,
    8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 0, 0, 16, 17,
    18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22,
    23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
];

#[rustfmt::skip]
pub(super) const LENGTH_CODE: [u8; 256] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 12, 12,
    13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16,
    17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19,
    19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
    21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 22, 22, 22, 22,
    22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
    23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28,
];

#[rustfmt::skip]
pub(super) const BASE_LENGTH: [u32; 29] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24,
    28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 0,
];

#[rustfmt::skip]
pub(super) const BASE_DIST: [u32; 30] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24,
    32, 48, 64, 96, 128, 192, 256, 384, 512, 768,
    1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576,
];
