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

    /// Field multiplication `self · rhs mod (2²⁵⁵ − 19)`. Corresponds to bc
    /// `X25519Field.Mul`, transcribed verbatim: a Karatsuba split of the 10 limbs into
    /// low `a = xₗ·yₗ` and high `b = xₕ·yₕ` halves, the cross term `c = (xₗ+xₕ)(yₗ+yₕ)`,
    /// with the `2²⁵⁵ ≡ 19` reduction (× 19/38/76) folded in. Products accumulate in
    /// `i64`; limbs are cast to `i64` up front (equivalent to bc's per-multiply `(long)`
    /// casts). Constant-time.
    pub fn mul(self, rhs: Fe) -> Fe {
        let x = self.0;
        let y = rhs.0;
        let (mut x0, mut x1, mut x2, mut x3, mut x4) =
            (x[0] as i64, x[1] as i64, x[2] as i64, x[3] as i64, x[4] as i64);
        let (mut y0, mut y1, mut y2, mut y3, mut y4) =
            (y[0] as i64, y[1] as i64, y[2] as i64, y[3] as i64, y[4] as i64);
        let (u0, u1, u2, u3, u4) = (x[5] as i64, x[6] as i64, x[7] as i64, x[8] as i64, x[9] as i64);
        let (v0, v1, v2, v3, v4) = (y[5] as i64, y[6] as i64, y[7] as i64, y[8] as i64, y[9] as i64);

        // a = xₗ · yₗ（低 5 limb）
        let mut a0 = x0 * y0;
        let mut a1 = x0 * y1 + x1 * y0;
        let mut a2 = x0 * y2 + x1 * y1 + x2 * y0;
        let mut a3 = x1 * y2 + x2 * y1;
        a3 <<= 1;
        a3 += x0 * y3 + x3 * y0;
        let mut a4 = x2 * y2;
        a4 <<= 1;
        a4 += x0 * y4 + x1 * y3 + x3 * y1 + x4 * y0;
        let mut a5 = x1 * y4 + x2 * y3 + x3 * y2 + x4 * y1;
        a5 <<= 1;
        let mut a6 = x2 * y4 + x4 * y2;
        a6 <<= 1;
        a6 += x3 * y3;
        let mut a7 = x3 * y4 + x4 * y3;
        let mut a8 = x4 * y4;
        a8 <<= 1;

        // b = xₕ · yₕ（高 5 limb）
        let b0 = u0 * v0;
        let b1 = u0 * v1 + u1 * v0;
        let b2 = u0 * v2 + u1 * v1 + u2 * v0;
        let mut b3 = u1 * v2 + u2 * v1;
        b3 <<= 1;
        b3 += u0 * v3 + u3 * v0;
        let mut b4 = u2 * v2;
        b4 <<= 1;
        b4 += u0 * v4 + u1 * v3 + u3 * v1 + u4 * v0;
        let b5 = u1 * v4 + u2 * v3 + u3 * v2 + u4 * v1;
        let mut b6 = u2 * v4 + u4 * v2;
        b6 <<= 1;
        b6 += u3 * v3;
        let b7 = u3 * v4 + u4 * v3;
        let b8 = u4 * v4;

        // 折疊 high 半部（2²⁵⁵ ≡ 19）
        a0 -= b5 * 76;
        a1 -= b6 * 38;
        a2 -= b7 * 38;
        a3 -= b8 * 76;
        a5 -= b0;
        a6 -= b1;
        a7 -= b2;
        a8 -= b3;

        // c = (xₗ+xₕ) · (yₗ+yₕ)（Karatsuba cross）
        x0 += u0; y0 += v0;
        x1 += u1; y1 += v1;
        x2 += u2; y2 += v2;
        x3 += u3; y3 += v3;
        x4 += u4; y4 += v4;

        let c0 = x0 * y0;
        let c1 = x0 * y1 + x1 * y0;
        let c2 = x0 * y2 + x1 * y1 + x2 * y0;
        let mut c3 = x1 * y2 + x2 * y1;
        c3 <<= 1;
        c3 += x0 * y3 + x3 * y0;
        let mut c4 = x2 * y2;
        c4 <<= 1;
        c4 += x0 * y4 + x1 * y3 + x3 * y1 + x4 * y0;
        let mut c5 = x1 * y4 + x2 * y3 + x3 * y2 + x4 * y1;
        c5 <<= 1;
        let mut c6 = x2 * y4 + x4 * y2;
        c6 <<= 1;
        c6 += x3 * y3;
        let c7 = x3 * y4 + x4 * y3;
        let mut c8 = x4 * y4;
        c8 <<= 1;

        // 收攏 + 進位（中間項 = c − a − b，折疊入結果）
        let mut z = [0i32; SIZE];
        let mut t = a8 + (c3 - a3);
        let z8 = t as i32 & M26;
        t >>= 26;
        t += (c4 - a4) - b4;
        let z9 = t as i32 & M25;
        t >>= 25;
        t = a0 + (t + c5 - a5) * 38;
        z[0] = t as i32 & M26;
        t >>= 26;
        t += a1 + (c6 - a6) * 38;
        z[1] = t as i32 & M26;
        t >>= 26;
        t += a2 + (c7 - a7) * 38;
        z[2] = t as i32 & M25;
        t >>= 25;
        t += a3 + (c8 - a8) * 38;
        z[3] = t as i32 & M26;
        t >>= 26;
        t += a4 + b4 * 38;
        z[4] = t as i32 & M25;
        t >>= 25;
        t += a5 + (c0 - a0);
        z[5] = t as i32 & M26;
        t >>= 26;
        t += a6 + (c1 - a1);
        z[6] = t as i32 & M26;
        t >>= 26;
        t += a7 + (c2 - a2);
        z[7] = t as i32 & M25;
        t >>= 25;
        t += z8 as i64;
        z[8] = t as i32 & M26;
        t >>= 26;
        z[9] = z9 + t as i32;
        Fe(z)
    }

    /// Field multiplication by a small `i32` scalar, `self · y mod (2²⁵⁵ − 19)`.
    /// Corresponds to bc `X25519Field.Mul(x, int y, z)` — each limb `× y` with carry
    /// propagation and the `2²⁵⁵ ≡ 19` fold (`× 38`). Used by the ladder (× A24).
    pub fn mul_i32(self, y: i32) -> Fe {
        let x = self.0;
        let (x0, x1, mut x2, x3, mut x4, x5, x6, mut x7, x8, mut x9) =
            (x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9]);
        let y = y as i64;
        let mut z = [0i32; SIZE];

        let mut c0 = x2 as i64 * y; x2 = c0 as i32 & M25; c0 >>= 25;
        let mut c1 = x4 as i64 * y; x4 = c1 as i32 & M25; c1 >>= 25;
        let mut c2 = x7 as i64 * y; x7 = c2 as i32 & M25; c2 >>= 25;
        let mut c3 = x9 as i64 * y; x9 = c3 as i32 & M25; c3 >>= 25;
        c3 *= 38;

        c3 += x0 as i64 * y; z[0] = c3 as i32 & M26; c3 >>= 26;
        c1 += x5 as i64 * y; z[5] = c1 as i32 & M26; c1 >>= 26;

        c3 += x1 as i64 * y; z[1] = c3 as i32 & M26; c3 >>= 26;
        c0 += x3 as i64 * y; z[3] = c0 as i32 & M26; c0 >>= 26;
        c1 += x6 as i64 * y; z[6] = c1 as i32 & M26; c1 >>= 26;
        c2 += x8 as i64 * y; z[8] = c2 as i32 & M26; c2 >>= 26;

        z[2] = x2 + c3 as i32;
        z[4] = x4 + c0 as i32;
        z[7] = x7 + c1 as i32;
        z[9] = x9 + c2 as i32;
        Fe(z)
    }

    /// Returns `self^(2ⁿ)` — `n` repeated squarings (`n >= 1`). Corresponds to bc
    /// `X25519Field.Sqr(x, n, z)`; used by the inversion addition chain.
    pub fn sqr_n(self, n: usize) -> Fe {
        debug_assert!(n > 0);
        let mut z = self.sqr();
        for _ in 1..n {
            z = z.sqr();
        }
        z
    }

    /// Field squaring `self² mod (2²⁵⁵ − 19)`. Corresponds to bc `X25519Field.Sqr`,
    /// transcribed verbatim: same Karatsuba structure as [`mul`](Fe::mul) but with the
    /// squaring symmetry (doubled `x_2` terms save half the products; folds use × 38,
    /// no × 76). Constant-time.
    pub fn sqr(self) -> Fe {
        let x = self.0;
        let (mut x0, mut x1, mut x2, mut x3, mut x4) =
            (x[0] as i64, x[1] as i64, x[2] as i64, x[3] as i64, x[4] as i64);
        let (u0, u1, u2, u3, u4) = (x[5] as i64, x[6] as i64, x[7] as i64, x[8] as i64, x[9] as i64);

        let mut x1_2 = x1 * 2;
        let mut x2_2 = x2 * 2;
        let mut x3_2 = x3 * 2;
        let mut x4_2 = x4 * 2;

        let mut a0 = x0 * x0;
        let mut a1 = x0 * x1_2;
        let mut a2 = x0 * x2_2 + x1 * x1;
        let mut a3 = x1_2 * x2_2 + x0 * x3_2;
        let a4 = x2 * x2_2 + x0 * x4_2 + x1 * x3_2;
        let mut a5 = x1_2 * x4_2 + x2_2 * x3_2;
        let mut a6 = x2_2 * x4_2 + x3 * x3;
        let mut a7 = x3 * x4_2;
        let mut a8 = x4 * x4_2;

        let u1_2 = u1 * 2;
        let u2_2 = u2 * 2;
        let u3_2 = u3 * 2;
        let u4_2 = u4 * 2;

        let b0 = u0 * u0;
        let b1 = u0 * u1_2;
        let b2 = u0 * u2_2 + u1 * u1;
        let b3 = u1_2 * u2_2 + u0 * u3_2;
        let b4 = u2 * u2_2 + u0 * u4_2 + u1 * u3_2;
        let b5 = u1_2 * u4_2 + u2_2 * u3_2;
        let b6 = u2_2 * u4_2 + u3 * u3;
        let b7 = u3 * u4_2;
        let b8 = u4 * u4_2;

        a0 -= b5 * 38;
        a1 -= b6 * 38;
        a2 -= b7 * 38;
        a3 -= b8 * 38;
        a5 -= b0;
        a6 -= b1;
        a7 -= b2;
        a8 -= b3;

        x0 += u0;
        x1 += u1;
        x2 += u2;
        x3 += u3;
        x4 += u4;

        x1_2 = x1 * 2;
        x2_2 = x2 * 2;
        x3_2 = x3 * 2;
        x4_2 = x4 * 2;

        let c0 = x0 * x0;
        let c1 = x0 * x1_2;
        let c2 = x0 * x2_2 + x1 * x1;
        let c3 = x1_2 * x2_2 + x0 * x3_2;
        let c4 = x2 * x2_2 + x0 * x4_2 + x1 * x3_2;
        let c5 = x1_2 * x4_2 + x2_2 * x3_2;
        let c6 = x2_2 * x4_2 + x3 * x3;
        let c7 = x3 * x4_2;
        let c8 = x4 * x4_2;

        let mut z = [0i32; SIZE];
        let mut t = a8 + (c3 - a3);
        let z8 = t as i32 & M26;
        t >>= 26;
        t += (c4 - a4) - b4;
        let z9 = t as i32 & M25;
        t >>= 25;
        t = a0 + (t + c5 - a5) * 38;
        z[0] = t as i32 & M26;
        t >>= 26;
        t += a1 + (c6 - a6) * 38;
        z[1] = t as i32 & M26;
        t >>= 26;
        t += a2 + (c7 - a7) * 38;
        z[2] = t as i32 & M25;
        t >>= 25;
        t += a3 + (c8 - a8) * 38;
        z[3] = t as i32 & M26;
        t >>= 26;
        t += a4 + b4 * 38;
        z[4] = t as i32 & M25;
        t >>= 25;
        t += a5 + (c0 - a0);
        z[5] = t as i32 & M26;
        t >>= 26;
        t += a6 + (c1 - a1);
        z[6] = t as i32 & M26;
        t >>= 26;
        t += a7 + (c2 - a2);
        z[7] = t as i32 & M25;
        t >>= 25;
        t += z8 as i64;
        z[8] = t as i32 & M26;
        t >>= 26;
        z[9] = z9 + t as i32;
        Fe(z)
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
            // add / sub / mul 對照真值
            assert_eq!(fe_val(a.add(b)), (&av + &bv).rem_euclid(&p));
            assert_eq!(fe_val(a.sub(b)), (&av - &bv).rem_euclid(&p));
            assert_eq!(fe_val(a.mul(b)), (&av * &bv).rem_euclid(&p));
            // sqr(a) == a² mod p == a·a
            assert_eq!(fe_val(a.sqr()), (&av * &av).rem_euclid(&p));
            assert_eq!(fe_val(a.sqr()), fe_val(a.mul(a)));
            // mul_i32（ladder 用 A24 = 121666）
            for &y in &[1i32, 19, 121665, 121666] {
                let yv = BigInteger::from_u32(y as u32);
                assert_eq!(fe_val(a.mul_i32(y)), (&av * &yv).rem_euclid(&p), "mul_i32 y={y}");
            }
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
