//! Shared full Ed25519 fixed-base multiplication for X25519 and RFC 8032.
//!
//! The SHA-512 signature layer lives in `tc_ed25519`. This module owns the
//! Edwards point formulas and compile-time table, avoiding a dependency cycle.

use crate::x25519::clamp_private_key;
use crate::x25519_field::Fe;

#[derive(Clone, Copy)]
struct EdPoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl EdPoint {
    const fn identity() -> Self {
        Self {
            x: Fe::zero(),
            y: Fe::one(),
            z: Fe::one(),
            t: Fe::zero(),
        }
    }

    fn add_precomputed(self, rhs: EdPrecomp) -> Self {
        // Hisil 等人的 complete extended-coordinate mixed-add 公式，a = -1。
        let a = self.y.sub(self.x).mul(rhs.y_minus_x);
        let b = self.y.add(self.x).mul(rhs.y_plus_x);
        let c = self.t.mul(rhs.xy2d);
        let d = self.z.add(self.z);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    fn double(self) -> Self {
        // Complete extended-coordinate doubling，a = -1。
        let a = self.x.sqr();
        let b = self.y.sqr();
        let c = self.z.sqr().mul_i32(2);
        let d = a.negate();
        let e = self.x.add(self.y).sqr().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }
}

#[derive(Clone, Copy)]
struct EdPrecomp {
    y_minus_x: Fe,
    y_plus_x: Fe,
    xy2d: Fe,
}

impl EdPrecomp {
    fn select(position: usize, digit: i8) -> Self {
        let signed = digit as i32;
        let negative = (signed >> 31) & 1;
        let absolute = ((signed ^ -negative) + negative) as u8;

        // abs(digit) == 0 時保留 Niels identity `(1, 1, 0)`。
        let mut packed = [[0_u64; 4]; 3];
        packed[0][0] = 1;
        packed[1][0] = 1;
        for (index, candidate) in BASE_TABLE[position].iter().enumerate() {
            let difference = (absolute ^ (index as u8 + 1)) as u64;
            let equal = ((difference | difference.wrapping_neg()) >> 63) ^ 1;
            let mask = 0_u64.wrapping_sub(equal);
            for coordinate in 0..3 {
                for word in 0..4 {
                    packed[coordinate][word] ^=
                        mask & (packed[coordinate][word] ^ candidate[coordinate][word]);
                }
            }
        }

        let mut selected = Self {
            y_minus_x: unpack(packed[0]),
            y_plus_x: unpack(packed[1]),
            xy2d: unpack(packed[2]),
        };
        let negative_y_minus_x = Fe::cmov(negative, selected.y_plus_x, selected.y_minus_x);
        selected.y_plus_x = Fe::cmov(negative, selected.y_minus_x, selected.y_plus_x);
        selected.y_minus_x = negative_y_minus_x;
        selected.xy2d = selected.xy2d.cnegate(negative);
        selected
    }
}

fn unpack(words: [u64; 4]) -> Fe {
    let mut bytes = [0_u8; 32];
    for (index, word) in words.iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    Fe::decode(&bytes)
}

/// 編譯期固定表已經完成預算；保留這個入口以對齊 bc 與未來完整 RFC 8032 API。
pub(crate) fn precompute() {
    core::hint::black_box(&BASE_TABLE);
}

/// 以 signed radix-16 固定視窗計算 Ed25519 基點倍數，回傳 projective `Y`、`Z`。
///
/// 表的第 `i` 列保存 `1..=8` 倍的 `256^i B`。先累加奇數 nibble、固定倍點
/// 四次，再累加偶數 nibble。完整 256-bit 路徑另外處理 signed recoding 的最高進位。
pub(crate) fn scalar_mult_base_yz(k: &[u8; 32]) -> (Fe, Fe) {
    let mut scalar = *k;
    clamp_private_key(&mut scalar);
    let (_, y, z, _) = scalar_mult_base(&scalar);
    (y, z)
}

/// Multiplies the Edwards base point by all 256 input bits, without clamping.
/// Returns extended `(X, Y, Z, T)` coordinates for the RFC 8032 layer.
/// The table is scanned with masks; no secret index is used.
pub fn scalar_mult_base(scalar: &[u8; 32]) -> (Fe, Fe, Fe, Fe) {
    let mut digits = [0_i8; 64];
    for (index, byte) in scalar.iter().enumerate() {
        digits[index * 2] = (byte & 0x0F) as i8;
        digits[index * 2 + 1] = (byte >> 4) as i8;
    }
    let mut carry = 0_i8;
    for digit in &mut digits[..63] {
        let value = *digit + carry;
        carry = (value + 8) >> 4;
        *digit = value - (carry << 4);
    }
    let top = digits[63] + carry;
    let overflow = (top + 8) >> 4;
    digits[63] = top - (overflow << 4);

    let mut result = EdPoint::identity();
    for position in 0..32 {
        result = result.add_precomputed(EdPrecomp::select(position, digits[position * 2 + 1]));
    }
    for _ in 0..4 {
        result = result.double();
    }
    for position in 0..32 {
        result = result.add_precomputed(EdPrecomp::select(position, digits[position * 2]));
    }
    // Signed recoding may produce a 257th bit. Derive 2^256 B from a
    // public table entry (8 * 256^31 B), then include it with a mask.
    let mut high = EdPoint::identity().add_precomputed(EdPrecomp::select(31, 8));
    for _ in 0..5 {
        high = high.double();
    }
    high.x = Fe::cmov(overflow as i32, high.x, Fe::zero());
    high.y = Fe::cmov(overflow as i32, high.y, Fe::one());
    high.z = Fe::cmov(overflow as i32, high.z, Fe::one());
    high.t = Fe::cmov(overflow as i32, high.t, Fe::zero());
    let d = Fe::edwards_d();
    let a = result.x.mul(high.x);
    let b = result.y.mul(high.y);
    let c = d.mul(result.t).mul(high.t);
    let z = result.z.mul(high.z);
    let e = result
        .x
        .add(result.y)
        .carry()
        .mul(high.x.add(high.y).carry())
        .sub(a)
        .sub(b)
        .carry();
    let f = z.sub(c).carry();
    let g = z.add(c).carry();
    let h = b.add(a).carry();
    (e.mul(f), g.mul(h), f.mul(g), e.mul(h))
}

// 每個欄位元素以 canonical 32-byte encoding 的四個 little-endian u64 保存，
// 選完才 decode，讓 256 點的靜態表維持 24 KiB。
include!("ed25519_base_table.rs");
