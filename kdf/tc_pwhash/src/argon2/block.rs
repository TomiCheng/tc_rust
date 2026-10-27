use tc_zeroize::Zeroize;

/// 1024 位元組的區塊，128 個小端序 u64。
pub(super) type Block = [u64; 128];

pub(super) fn block_from_bytes(block: &mut Block, bytes: &[u8; 1024]) {
    for (word, chunk) in block.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut le = [0; 8];
        le.copy_from_slice(chunk);
        *word = u64::from_le_bytes(le);
    }
}

pub(super) fn block_to_bytes(block: &Block, bytes: &mut [u8; 1024]) {
    for (chunk, word) in bytes.chunks_exact_mut(8).zip(block) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
}

/// 壓縮函數 G 的工作區，BC 的 `FillBlock`：R、Z 與 Argon2i 的位址區塊，drop 時清除。
pub(super) struct Filler {
    r: Block,
    z: Block,
    pub(super) input: Block,
    pub(super) address: Block,
}

impl Filler {
    pub(super) fn new() -> Self {
        Self {
            r: [0; 128],
            z: [0; 128],
            input: [0; 128],
            address: [0; 128],
        }
    }

    /// R = X ⊕ Y；與 [`store`](Self::store) 分開，X、Y 可以和目標是同一塊記憶體的不同區塊。
    pub(super) fn load(&mut self, x: &Block, y: &Block) {
        for ((r, x), y) in self.r.iter_mut().zip(x).zip(y) {
            *r = x ^ y;
        }
    }

    /// current = R ⊕ P(R)；`with_xor` 時 XOR 進 current（v1.3 第二輪起）。
    pub(super) fn store(&mut self, current: &mut Block, with_xor: bool) {
        self.mix();
        let mixed = self.r.iter().zip(&self.z);
        if with_xor {
            for (c, (r, z)) in current.iter_mut().zip(mixed) {
                *c ^= r ^ z;
            }
        } else {
            for (c, (r, z)) in current.iter_mut().zip(mixed) {
                *c = r ^ z;
            }
        }
    }

    /// 下一塊位址：input 的計數加一，address = G(0, G(0, input))。
    pub(super) fn next_addresses(&mut self) {
        self.input[6] += 1;
        self.r = self.input;
        self.mix_into_address();
        self.r = self.address;
        self.mix_into_address();
    }

    fn mix_into_address(&mut self) {
        self.mix();
        for (a, (r, z)) in self.address.iter_mut().zip(self.r.iter().zip(&self.z)) {
            *a = r ^ z;
        }
    }

    fn mix(&mut self) {
        self.z = self.r;
        permute_block(&mut self.z);
    }
}

impl Drop for Filler {
    fn drop(&mut self) {
        self.r.zeroize();
        self.z.zeroize();
        self.input.zeroize();
        self.address.zeroize();
    }
}

/// RFC 9106 §3.5：區塊看成 8×8 個 16 位元組暫存器，先對每列、再對每行套 P。
fn permute_block(v: &mut Block) {
    for row in (0..128).step_by(16) {
        permute(v, core::array::from_fn(|k| row + k));
    }
    for column in (0..16).step_by(2) {
        permute(v, core::array::from_fn(|k| column + (k / 2) * 16 + k % 2));
    }
}

fn permute(v: &mut Block, s: [usize; 16]) {
    gb(v, s[0], s[4], s[8], s[12]);
    gb(v, s[1], s[5], s[9], s[13]);
    gb(v, s[2], s[6], s[10], s[14]);
    gb(v, s[3], s[7], s[11], s[15]);
    gb(v, s[0], s[5], s[10], s[15]);
    gb(v, s[1], s[6], s[11], s[12]);
    gb(v, s[2], s[7], s[8], s[13]);
    gb(v, s[3], s[4], s[9], s[14]);
}

/// BLAKE2b 的 G，加法改成 a + b + 2·lo(a)·lo(b)。
fn gb(v: &mut Block, a: usize, b: usize, c: usize, d: usize) {
    v[a] = mul_add(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = mul_add(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = mul_add(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = mul_add(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn mul_add(x: u64, y: u64) -> u64 {
    let product = (x & 0xffff_ffff) * (y & 0xffff_ffff);
    x.wrapping_add(y).wrapping_add(product << 1)
}
