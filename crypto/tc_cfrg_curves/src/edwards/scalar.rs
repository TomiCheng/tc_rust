//! Fixed-schedule scalar reduction and multiply-add. Moduli are public.
use tc_constant_time::{Choice, ConditionallySelectable};

/// A reduced little-endian scalar. No secret-dependent integer normalization.
#[derive(Clone, Copy)]
pub struct Scalar<const N: usize>([u32; N]);
impl<const N: usize> Scalar<N> {
    /// Reduces every byte, processing leading zeros. Input length is public.
    pub fn reduce(bytes: &[u8], modulus: &[u32; N]) -> Self {
        let mut result = Self([0; N]);
        let mut one = [0; N];
        one[0] = 1;
        for byte in bytes.iter().rev() {
            for bit in (0..8).rev() {
                result = result.add(&result, modulus);
                let incremented = result.add(&Self(one), modulus);
                result.0 = <[u32; N]>::conditional_select(
                    &result.0,
                    &incremented.0,
                    Choice::from_lsb(byte >> bit),
                );
            }
        }
        result
    }
    /// Returns whether a public encoding is canonical (strictly below modulus).
    pub fn is_canonical(bytes: &[u8], modulus: &[u32; N]) -> bool {
        if bytes.len() > N * 4 && bytes[N * 4..].iter().any(|b| *b != 0) {
            return false;
        }
        let mut words = [0; N];
        for (i, byte) in bytes.iter().take(N * 4).enumerate() {
            words[i / 4] |= (*byte as u32) << (8 * (i % 4));
        }
        for i in (0..N).rev() {
            if words[i] != modulus[i] {
                return words[i] < modulus[i];
            }
        }
        false
    }
    /// Writes a fixed-size encoding; extra output bytes are zero.
    pub fn encode(&self, output: &mut [u8]) {
        assert!(output.len() >= N * 4);
        output.fill(0);
        for (i, word) in self.0.iter().enumerate() {
            output[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    fn add(&self, rhs: &Self, modulus: &[u32; N]) -> Self {
        let mut carry = 0_u64;
        let sum = core::array::from_fn(|i| {
            let v = self.0[i] as u64 + rhs.0[i] as u64 + carry;
            carry = v >> 32;
            v as u32
        });
        let mut borrow = 0_i64;
        let reduced = core::array::from_fn(|i| {
            let v = sum[i] as i64 - modulus[i] as i64 - borrow;
            borrow = (v >> 63) & 1;
            v as u32
        });
        Self(<[u32; N]>::conditional_select(
            &sum,
            &reduced,
            Choice::from_lsb(carry as u8 | (borrow as u8 ^ 1)),
        ))
    }
    /// Computes `self * rhs + addend` modulo the public order.
    pub fn mul_add(&self, rhs: &Self, addend: &Self, modulus: &[u32; N]) -> Self {
        let mut result = Self([0; N]);
        for word in rhs.0.iter().rev() {
            for bit in (0..32).rev() {
                result = result.add(&result, modulus);
                let next = result.add(self, modulus);
                result.0 = <[u32; N]>::conditional_select(
                    &result.0,
                    &next.0,
                    Choice::from_lsb((word >> bit) as u8),
                );
            }
        }
        result.add(addend, modulus)
    }
}
