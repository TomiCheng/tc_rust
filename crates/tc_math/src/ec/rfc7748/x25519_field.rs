//! Arithmetic in the field `GF(2²⁵⁵ − 19)`, the base field of Curve25519 / X25519.
//!
//! Ported from Bouncy Castle's `Org.BouncyCastle.Math.EC.Rfc7748.X25519Field`
//! (scalar path; the AVX2/SSE2 vector paths are skipped, like binpoly's SIMD).
//!
//! # Representation (ref10, radix 2²⁵·⁵)
//!
//! A field element is [`SIZE`] = 10 signed 32-bit limbs, holding a 255-bit value in
//! roughly **radix 2²⁵·⁵**: each limb holds 25–26 bits (see [`Fe::carry`] for bc's
//! exact per-limb widths — the 25-bit limbs are indices 2, 4, 7, 9). Each limb lives
//! in an `i32` but uses only 25–26 bits, so the spare high bits absorb carries — the
//! representation is **unsaturated**:
//! addition is limb-wise `i32` add with no immediate carry, and [`carry`]/`normalize`
//! reconcile later. Products of two ~26-bit limbs (~52 bits) accumulate in `i64`, so
//! no 128-bit arithmetic is needed.
//!
//! All operations are **constant-time** (straight-line, no data-dependent branches):
//! this field is the constant-time answer for its curve, unlike the variable-time
//! generic Fp/F2m layers.
//
// TODO(x25519-field-5limb): on 64-bit targets a radix-2⁵¹ representation (5 × u64,
// products in u128) is substantially faster — ~1/4 the partial products and full use
// of the 64-bit multiplier (as in TweetNaCl / ref10-64 / fiat-crypto). It is a
// *separate* implementation, not a limb-width cfg of this one (limb count, radix, and
// the ×19/38/76 reduction constants all change together). Deferred as a 64-bit
// optimization; this 10×i32 port is the faithful, all-platform baseline.

/// Number of `i32` limbs in a field element (radix 2²⁵·⁵).
pub const SIZE: usize = 10;

/// Mask for a 24-bit limb (`2²⁴ − 1`). bc `X25519Field.M24`; used to drop bit 255 on
/// decode (RFC 7748).
const M24: i32 = 0x00FF_FFFF;
/// Mask for a 25-bit limb (`2²⁵ − 1`). bc `X25519Field.M25`.
const M25: i32 = 0x01FF_FFFF;
/// Mask for a 26-bit limb (`2²⁶ − 1`). bc `X25519Field.M26`.
const M26: i32 = 0x03FF_FFFF;

/// An element of `GF(2²⁵⁵ − 19)` in the ref10 radix-2²⁵·⁵ representation: [`SIZE`]
/// signed limbs, unsaturated (each limb uses 25–26 of its 32 bits). Values are not
/// necessarily reduced/normalized between operations; [`carry`]/`normalize` bring a
/// limb array back into range when needed.
///
/// `Copy` — it is a small fixed array on the stack, so value-returning arithmetic
/// costs no heap allocation (cleaner than bc's out-parameter style).
///
/// The limbs are **private**: they are an unsaturated, non-unique internal encoding
/// (the same field value has many limb representations), so all access goes through
/// this module's value-semantic API (arithmetic, `encode`/`decode`, constants).
#[derive(Clone, Copy, Debug)]
pub struct Fe([i32; SIZE]);

impl Fe {
    /// The additive identity `0` (all limbs zero). Corresponds to bc `X25519Field.Zero`
    /// (bc zeroes an out-parameter; we return a value — `Fe` is a `Copy` stack array,
    /// so this is allocation-free).
    pub const fn zero() -> Fe {
        Fe([0; SIZE])
    }

    /// The multiplicative identity `1` (limb 0 is `1`, the rest `0`). Corresponds to bc
    /// `X25519Field.One`.
    pub const fn one() -> Fe {
        let mut z = [0; SIZE];
        z[0] = 1;
        Fe(z)
    }

    /// Field addition: limb-wise `i32` add, **without carrying** — the unsaturated
    /// representation absorbs the growth. Corresponds to bc `X25519Field.Add` (scalar
    /// path; the AVX2/SSE2 vector paths are skipped — see `TODO(x25519-simd)`).
    ///
    /// The result is *not* normalized: chain a few `add`/`sub`, then `carry` (added
    /// later) before a `mul`/`sqr`, which need limbs back in range.
    pub fn add(self, rhs: Fe) -> Fe {
        Fe(core::array::from_fn(|i| self.0[i] + rhs.0[i]))
    }

    /// Field subtraction: limb-wise `i32` subtract, **without carrying**. Limbs are
    /// signed, so a negative difference is fine — the unsaturated representation and a
    /// later `carry` absorb it. Corresponds to bc `X25519Field.Sub` (scalar path).
    pub fn sub(self, rhs: Fe) -> Fe {
        Fe(core::array::from_fn(|i| self.0[i] - rhs.0[i]))
    }

    /// Propagates carries so the (unsaturated) limbs return to range, folding the
    /// top-limb overflow back via `2²⁵⁵ ≡ 19` (the `× 38` factor, in radix 2²⁵·⁵).
    /// The 25-bit limbs are indices 2, 4, 7, 9; the rest are 26-bit.
    ///
    /// Corresponds to bc `X25519Field.Carry`, transcribed verbatim. Rust `i32 >> n` is
    /// an arithmetic shift (like C# `int >>`), so signed limbs carry correctly.
    pub fn carry(self) -> Fe {
        let [mut z0, mut z1, mut z2, mut z3, mut z4, mut z5, mut z6, mut z7, mut z8, mut z9] =
            self.0;

        z2 += z1 >> 26; z1 &= M26;
        z4 += z3 >> 26; z3 &= M26;
        z7 += z6 >> 26; z6 &= M26;
        z9 += z8 >> 26; z8 &= M26;

        z3 += z2 >> 25; z2 &= M25;
        z5 += z4 >> 25; z4 &= M25;
        z8 += z7 >> 25; z7 &= M25;
        z0 += (z9 >> 25) * 38; z9 &= M25; // 2²⁵⁵ ≡ 19 折疊(×38）

        z1 += z0 >> 26; z0 &= M26;
        z6 += z5 >> 26; z5 &= M26;

        z2 += z1 >> 26; z1 &= M26;
        z4 += z3 >> 26; z3 &= M26;
        z7 += z6 >> 26; z6 &= M26;
        z9 += z8 >> 26; z8 &= M26;

        Fe([z0, z1, z2, z3, z4, z5, z6, z7, z8, z9])
    }

    /// Reduces to the canonical representative in `[0, p)` (`p = 2²⁵⁵ − 19`), so that
    /// [`encode`](Fe::encode) yields the unique little-endian bytes. Corresponds to bc
    /// `X25519Field.Normalize` (preceded by a [`carry`](Fe::carry) — bc's precondition).
    ///
    /// Constant-time: the conditional subtraction of `p` is done branchlessly via two
    /// [`Fe::reduce`] calls with `±x`.
    pub fn normalize(self) -> Fe {
        let z = self.carry();
        let x = (z.0[9] >> (24 - 1)) & 1;
        let z = z.reduce(x).reduce(-x);
        debug_assert_eq!(z.0[9] >> 24, 0);
        z
    }

    /// One reduction pass: fold the bits of `z[9]` above 24 back via `2²⁵⁵ ≡ 19`
    /// (`× 19`), add `x` at the top first, and carry-propagate. bc `X25519Field.Reduce`,
    /// transcribed verbatim (limb widths 26,26,25,26,25,26,26,25,26,24).
    fn reduce(self, x: i32) -> Fe {
        let mut z = self.0;
        let z9 = z[9] & M24;
        let t = (z[9] >> 24) + x;

        let mut cc: i64 = t as i64 * 19;
        cc += z[0] as i64; z[0] = cc as i32 & M26; cc >>= 26;
        cc += z[1] as i64; z[1] = cc as i32 & M26; cc >>= 26;
        cc += z[2] as i64; z[2] = cc as i32 & M25; cc >>= 25;
        cc += z[3] as i64; z[3] = cc as i32 & M26; cc >>= 26;
        cc += z[4] as i64; z[4] = cc as i32 & M25; cc >>= 25;
        cc += z[5] as i64; z[5] = cc as i32 & M26; cc >>= 26;
        cc += z[6] as i64; z[6] = cc as i32 & M26; cc >>= 26;
        cc += z[7] as i64; z[7] = cc as i32 & M25; cc >>= 25;
        cc += z[8] as i64; z[8] = cc as i32 & M26; cc >>= 26;
        z[9] = z9 + cc as i32;
        Fe(z)
    }

    /// Encodes a **normalized** field element to 32 little-endian bytes (the X25519
    /// wire format). Corresponds to bc `X25519Field.Encode`.
    ///
    /// The input must be carried and fully reduced (via `normalize`, added next);
    /// otherwise the result is not the canonical little-endian value.
    pub fn encode(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        encode_128(&self.0[0..5], &mut out[0..16]);
        encode_128(&self.0[5..10], &mut out[16..32]);
        out
    }

    /// Decodes 32 little-endian bytes into a field element. The top bit (bit 255) is
    /// masked off per RFC 7748. Corresponds to bc `X25519Field.Decode` (= `Decode255`).
    ///
    /// Limbs land in range but the value may be `≥ p` (in `[p, 2²⁵⁵)`); `normalize`
    /// reduces to the canonical representative when needed.
    pub fn decode(bytes: &[u8; 32]) -> Fe {
        let mut z = [0i32; SIZE];
        decode_128(&bytes[0..16], &mut z[0..5]);
        decode_128(&bytes[16..32], &mut z[5..10]);
        z[9] &= M24; // 丟掉 bit 255（RFC 7748）
        Fe(z)
    }
}

/// Packs 5 limbs (widths 26, 26, 25, 26, 25 = 128 bits) into 16 little-endian bytes.
/// bc `X25519Field.Encode128` (+ `Encode32`, folded in via `to_le_bytes`).
fn encode_128(x: &[i32], bs: &mut [u8]) {
    let (x0, x1, x2, x3, x4) = (x[0] as u32, x[1] as u32, x[2] as u32, x[3] as u32, x[4] as u32);
    let t0 = x0 | (x1 << 26);
    let t1 = (x1 >> 6) | (x2 << 20);
    let t2 = (x2 >> 12) | (x3 << 13);
    let t3 = (x3 >> 19) | (x4 << 7);
    bs[0..4].copy_from_slice(&t0.to_le_bytes());
    bs[4..8].copy_from_slice(&t1.to_le_bytes());
    bs[8..12].copy_from_slice(&t2.to_le_bytes());
    bs[12..16].copy_from_slice(&t3.to_le_bytes());
}

/// Unpacks 16 little-endian bytes into 5 limbs (inverse of [`encode_128`]).
/// bc `X25519Field.Decode128`.
fn decode_128(bs: &[u8], z: &mut [i32]) {
    let t0 = u32::from_le_bytes(bs[0..4].try_into().unwrap());
    let t1 = u32::from_le_bytes(bs[4..8].try_into().unwrap());
    let t2 = u32::from_le_bytes(bs[8..12].try_into().unwrap());
    let t3 = u32::from_le_bytes(bs[12..16].try_into().unwrap());
    z[0] = (t0 & M26 as u32) as i32;
    z[1] = (((t1 << 6) | (t0 >> 26)) & M26 as u32) as i32;
    z[2] = (((t2 << 12) | (t1 >> 20)) & M25 as u32) as i32;
    z[3] = (((t3 << 19) | (t2 >> 13)) & M26 as u32) as i32;
    z[4] = (t3 >> 7) as i32;
}

// TODO(x25519-simd): bc's Add/Mul/etc. have AVX2/SSE2 vector paths behind runtime
// feature detection (Sse2.IsEnabled / Avx2.IsEnabled). We port only the scalar path.
// A portable runtime-dispatched SIMD backend in no_std needs hand-rolled CPUID
// (+ XGETBV for AVX) cached in an AtomicU8; `is_x86_feature_detected!` is std-only.
// Deferred; release builds already auto-vectorize the simple loops (add/sub) to SSE2.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::big_integer::BigInteger;

    fn p() -> BigInteger {
        // p = 2²⁵⁵ − 19
        &(&BigInteger::from_u32(1) << 255) - &BigInteger::from_u32(19)
    }

    // 一個 Fe 的真值:normalize → encode → 讀成 BigInteger。
    fn fe_val(fe: Fe) -> BigInteger {
        BigInteger::from_bytes_le_unsigned(&fe.normalize().encode())
    }

    // 一組 bytes 代表的值(decode 會丟 bit 255,故先清)。
    fn bytes_val(bytes: &[u8; 32]) -> BigInteger {
        let mut b = *bytes;
        b[31] &= 0x7F;
        BigInteger::from_bytes_le_unsigned(&b)
    }

    #[test]
    fn field_ops_match_bigint_mod_p() {
        let p = p();
        let mut s = 0xC0FFEE_1234_5678u64;
        let mut rand = || {
            let mut b = [0u8; 32];
            for x in b.iter_mut() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *x = s as u8;
            }
            b
        };
        for _ in 0..300 {
            let (ba, bb) = (rand(), rand());
            let a = Fe::decode(&ba);
            let b = Fe::decode(&bb);
            let av = bytes_val(&ba).rem_euclid(&p);
            let bv = bytes_val(&bb).rem_euclid(&p);

            // decode + normalize + encode 對照 (bytes mod p)
            assert_eq!(fe_val(a), av);
            assert_eq!(fe_val(b), bv);
            // add / sub 對照真值
            assert_eq!(fe_val(a.add(b)), (&av + &bv).rem_euclid(&p));
            assert_eq!(fe_val(a.sub(b)), (&av - &bv).rem_euclid(&p));
        }
    }

    #[test]
    fn zero_has_all_limbs_clear() {
        assert_eq!(Fe::zero().0, [0i32; SIZE]);
    }

    #[test]
    fn one_is_limb0() {
        assert_eq!(Fe::one().0, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn add_is_limbwise() {
        let a = Fe([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let b = Fe([10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        assert_eq!(a.add(b).0, [11, 22, 33, 44, 55, 66, 77, 88, 99, 110]);
        // a + 0 = a
        assert_eq!(a.add(Fe::zero()).0, a.0);
    }

    #[test]
    fn sub_is_limbwise() {
        let a = Fe([10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        let b = Fe([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(a.sub(b).0, [9, 18, 27, 36, 45, 54, 63, 72, 81, 90]);
        // a − a = 0；有號 limb 可為負：b − a
        assert_eq!(a.sub(a).0, [0i32; SIZE]);
        assert_eq!(b.sub(a).0, [-9, -18, -27, -36, -45, -54, -63, -72, -81, -90]);
    }

    #[test]
    fn carry_keeps_zero_and_one() {
        assert_eq!(Fe::zero().carry().0, Fe::zero().0);
        assert_eq!(Fe::one().carry().0, Fe::one().0);
    }

    #[test]
    fn carry_propagates_limb0_overflow() {
        // limb0 = 2²⁶ 溢位 → 進位到 limb1（同值：limb1 的權重就是 2²⁶）。
        let mut a = [0i32; SIZE];
        a[0] = 1 << 26;
        let mut expect = [0i32; SIZE];
        expect[1] = 1;
        assert_eq!(Fe(a).carry().0, expect);
    }

    #[test]
    fn carry_brings_limbs_into_range() {
        // 幾次滿載相加後 limb 超出範圍；carry 後每個 limb 應收回小範圍。
        let full = Fe([M26, M25, M26, M25, M26, M26, M25, M26, M25, M26]);
        let big = full.add(full).add(full); // 3× 滿載
        for (i, &limb) in big.carry().0.iter().enumerate() {
            assert!(limb.unsigned_abs() < (1u32 << 27), "limb {i} = {limb} 未收攏");
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        // bit 255 = 0 的 bytes：decode → encode 是純位元重排,應原樣還原。
        let mut s = 0x1234_5678_9ABC_DEF0u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..200 {
            let mut bytes = [0u8; 32];
            for b in bytes.iter_mut() {
                *b = next() as u8;
            }
            bytes[31] &= 0x7F; // 清掉 bit 255
            assert_eq!(Fe::decode(&bytes).encode(), bytes);
        }
        // zero / one 的編碼。
        assert_eq!(Fe::zero().encode(), [0u8; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(Fe::one().encode(), one);
        assert_eq!(Fe::decode(&one).encode(), one);
    }
}
