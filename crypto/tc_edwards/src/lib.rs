#![no_std]
//! Shared implementation details for the RFC 8032 signature crates.
//! Field arithmetic stays in `tc_rfc7748`; hashing stays in the signature layer.
//! These interfaces are draft and are not a general-purpose curve API.
mod scalar;
pub use scalar::Scalar;
use tc_constant_time::{Choice, ConstantTimeEq};
pub use tc_rfc7748::{x448_field::Fe448, x25519_field::Fe};

/// Edwards field and encoding parameters. Public-input decoding may vary in time.
pub trait EdwardsField: Copy {
    const BYTES: usize;
    const NEGATIVE_A: bool;
    fn zero() -> Self;
    fn one() -> Self;
    fn d() -> Self;
    fn add(self, b: Self) -> Self;
    fn sub(self, b: Self) -> Self;
    fn mul(self, b: Self) -> Self;
    fn invert(self) -> Self;
    fn select(a: Self, b: Self, c: Choice) -> Self;
    fn encode(self, output: &mut [u8]);
    fn decode(input: &[u8]) -> Option<Self>;
    fn sqrt_ratio(u: Self, v: Self) -> Option<Self>;
}
impl EdwardsField for Fe {
    const BYTES: usize = 32;
    const NEGATIVE_A: bool = true;
    fn zero() -> Self {
        Self::zero()
    }
    fn one() -> Self {
        Self::one()
    }
    fn d() -> Self {
        Self::edwards_d()
    }
    fn add(self, b: Self) -> Self {
        self.add(b).carry()
    }
    fn sub(self, b: Self) -> Self {
        self.sub(b).carry()
    }
    fn mul(self, b: Self) -> Self {
        self.mul(b)
    }
    fn invert(self) -> Self {
        self.invert()
    }
    fn select(a: Self, b: Self, c: Choice) -> Self {
        Self::cmov(c, b, a)
    }
    fn encode(self, output: &mut [u8]) {
        output.copy_from_slice(&self.normalize().encode());
    }
    fn decode(input: &[u8]) -> Option<Self> {
        let bytes: &[u8; 32] = input.try_into().ok()?;
        let value = Self::decode_255(bytes);
        (value.normalize().encode() == *bytes).then_some(value)
    }
    fn sqrt_ratio(u: Self, v: Self) -> Option<Self> {
        Self::sqrt_ratio_var(u, v)
    }
}
impl EdwardsField for Fe448 {
    const BYTES: usize = 57;
    const NEGATIVE_A: bool = false;
    fn zero() -> Self {
        Self::zero()
    }
    fn one() -> Self {
        Self::one()
    }
    fn d() -> Self {
        Self::one().mul_u32(39081).negate()
    }
    fn add(self, b: Self) -> Self {
        self.add(b)
    }
    fn sub(self, b: Self) -> Self {
        self.sub(b)
    }
    fn mul(self, b: Self) -> Self {
        self.mul(b)
    }
    fn invert(self) -> Self {
        self.invert()
    }
    fn select(a: Self, b: Self, c: Choice) -> Self {
        Self::cmov(c, a, b)
    }
    fn encode(self, output: &mut [u8]) {
        output[..56].copy_from_slice(&self.encode());
        output[56] = 0;
    }
    fn decode(input: &[u8]) -> Option<Self> {
        if input.len() != 57 || input[56] != 0 {
            return None;
        }
        let bytes: &[u8; 56] = input[..56].try_into().ok()?;
        let value = Self::decode(bytes);
        (value.encode() == *bytes).then_some(value)
    }
    fn sqrt_ratio(u: Self, v: Self) -> Option<Self> {
        Self::sqrt_ratio_var(u, v)
    }
}

/// Extended Edwards coordinates. No Debug to avoid accidental secret logging.
#[derive(Clone, Copy)]
pub struct EdwardsPoint<F: EdwardsField> {
    x: F,
    y: F,
    z: F,
    t: F,
    d: F,
}
impl<F: EdwardsField> EdwardsPoint<F> {
    pub fn identity() -> Self {
        Self {
            x: F::zero(),
            y: F::one(),
            z: F::one(),
            t: F::zero(),
            d: F::d(),
        }
    }
    pub fn from_extended(x: F, y: F, z: F, t: F) -> Self {
        Self {
            x,
            y,
            z,
            t,
            d: F::d(),
        }
    }
    /// Decodes canonical compressed coordinates, rejecting negative zero.
    pub fn decode(input: &[u8]) -> Option<Self> {
        if input.len() != F::BYTES {
            return None;
        }
        let mut bytes = [0_u8; 57];
        bytes[..input.len()].copy_from_slice(input);
        let sign = bytes[input.len() - 1] >> 7;
        bytes[input.len() - 1] &= 127;
        let y = F::decode(&bytes[..input.len()])?;
        let y2 = y.mul(y);
        let d = F::d();
        let numerator = F::one().sub(y2);
        let a = if F::NEGATIVE_A {
            F::zero().sub(F::one())
        } else {
            F::one()
        };
        let denominator = a.sub(d.mul(y2));
        let mut x = F::sqrt_ratio(numerator, denominator)?;
        let mut encoded = [0_u8; 57];
        x.encode(&mut encoded[..F::BYTES]);
        if encoded[..F::BYTES].iter().all(|b| *b == 0) && sign != 0 {
            return None;
        }
        x = F::select(
            x,
            F::zero().sub(x),
            Choice::from_lsb((encoded[0] & 1) ^ sign),
        );
        Some(Self {
            x,
            y,
            z: F::one(),
            t: x.mul(y),
            d,
        })
    }
    /// Encodes using a fixed-schedule inversion and field encoding.
    pub fn encode(&self, output: &mut [u8]) {
        assert_eq!(output.len(), F::BYTES);
        let inverse = self.z.invert();
        let x = self.x.mul(inverse);
        let y = self.y.mul(inverse);
        y.encode(output);
        let mut xb = [0_u8; 57];
        x.encode(&mut xb[..F::BYTES]);
        output[F::BYTES - 1] |= (xb[0] & 1) << 7;
    }
    pub fn add(&self, rhs: &Self) -> Self {
        let a = self.x.mul(rhs.x);
        let b = self.y.mul(rhs.y);
        let c = self.d.mul(self.t).mul(rhs.t);
        let d = self.z.mul(rhs.z);
        let e = self.x.add(self.y).mul(rhs.x.add(rhs.y)).sub(a).sub(b);
        let f = d.sub(c);
        let g = d.add(c);
        let h = if F::NEGATIVE_A { b.add(a) } else { b.sub(a) };
        Self {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
            d: self.d,
        }
    }
    fn select(a: Self, b: Self, c: Choice) -> Self {
        Self {
            x: F::select(a.x, b.x, c),
            y: F::select(a.y, b.y, c),
            z: F::select(a.z, b.z, c),
            t: F::select(a.t, b.t, c),
            d: a.d,
        }
    }
    /// Fixed radix-16 multiplication, consuming every scalar byte.
    pub fn multiply(&self, scalar: &[u8]) -> Self {
        let mut table = [Self::identity(); 16];
        for i in 1..16 {
            table[i] = table[i - 1].add(self);
        }
        let mut result = table[0];
        for byte in scalar.iter().rev() {
            for shift in [4, 0] {
                for _ in 0..4 {
                    result = result.add(&result);
                }
                let digit = (byte >> shift) & 15;
                let mut selected = table[0];
                for (i, point) in table.iter().enumerate() {
                    selected = Self::select(selected, *point, (i as u8).ct_eq(&digit));
                }
                result = result.add(&selected);
            }
        }
        result
    }
    /// Public-input identity check for verification.
    pub fn is_identity(&self) -> bool {
        let mut bytes = [0_u8; 57];
        self.encode(&mut bytes[..F::BYTES]);
        bytes[0] == 1 && bytes[1..F::BYTES].iter().all(|b| *b == 0)
    }
    /// Public-input projective equality via canonical encodings.
    pub fn equals(&self, rhs: &Self) -> bool {
        let mut a = [0_u8; 57];
        let mut b = [0_u8; 57];
        self.encode(&mut a[..F::BYTES]);
        rhs.encode(&mut b[..F::BYTES]);
        a == b
    }
}

/// Contexts in RFC 8032 are limited to 255 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextTooLong;
impl core::fmt::Display for ContextTooLong {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EdDSA context exceeds 255 bytes")
    }
}
impl core::error::Error for ContextTooLong {}
