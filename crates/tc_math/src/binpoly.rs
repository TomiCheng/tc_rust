//! Binary-polynomial arithmetic over `GF(2)[x]` — the backend for binary-field
//! (F2m) elliptic curves.
//!
//! Ported from Bouncy Castle's `Org.BouncyCastle.Math.BinPoly`. The element type
//! is [`BinaryPoly`], a value wrapping a fixed-length `Box<[u64]>`: the limbs are
//! **little-endian word order**, bit `i` (limb `i / 64`, bit `i % 64`) the
//! coefficient of `xⁱ`. A polynomial of degree `< n` occupies [`size`]`(n)` limbs,
//! zero-padded.
//!
//! [`BinaryPoly`] carries only the **reduction-independent** operations — the ones
//! whose result never depends on the reduction polynomial `r(x)`: addition
//! (limb-wise XOR), the constants `0`/`1`, and comparisons. Reduction-dependent
//! multiplication/inversion live in submodules and act on a [`BinaryPoly`]'s limbs
//! through a field operator that carries `r(x)`.
//!
//! Under the hood the constant-time comparisons compute a `u64` **mask**
//! (`u64::MAX` / `0`) so they can be combined branchlessly on secret-bearing
//! polynomials — matching Bouncy Castle's `Nat.*64` surface.

use alloc::boxed::Box;
use alloc::vec;
use core::ops::{Add, AddAssign};

// scalar 後端:carryless 乘法 kernel（leaf；Karatsuba 之後補）。
mod scalar;

// 對約簡多項式 r(x) 取模（把雙倍寬積摺回體元素）。每種形狀一個檔（對齊 bc）。
mod reduce_pentanomial;
mod reduce_trinomial;

/// Number of `u64` limbs required to hold a polynomial of bit length `n`
/// (`⌈n / 64⌉`).
pub fn size(n: usize) -> usize {
    n.div_ceil(64)
}

/// A binary polynomial over `GF(2)`, bit-packed into a fixed-length `Box<[u64]>`
/// (little-endian word order). See the [module docs](self) for the bit layout.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BinaryPoly {
    limbs: Box<[u64]>,
}

impl BinaryPoly {
    /// The zero polynomial in `size` limbs.
    pub fn zero(size: usize) -> Self {
        BinaryPoly { limbs: vec![0u64; size].into_boxed_slice() }
    }

    /// The polynomial `1` (low bit set, all other bits clear) in `size` limbs.
    ///
    /// # Panics
    ///
    /// Panics if `size == 0` (the polynomial `1` needs at least one limb).
    pub fn one(size: usize) -> Self {
        let mut limbs = vec![0u64; size];
        limbs[0] = 1; // size==0 → panic（1 至少要一個 limb）
        BinaryPoly { limbs: limbs.into_boxed_slice() }
    }

    /// Wraps an existing limb array as a polynomial (little-endian word order).
    pub fn from_limbs(limbs: impl Into<Box<[u64]>>) -> Self {
        BinaryPoly { limbs: limbs.into() }
    }

    /// Number of `u64` limbs backing this polynomial.
    pub fn size(&self) -> usize {
        self.limbs.len()
    }

    /// The backing limbs (little-endian word order), for the reduction-dependent
    /// operator layer.
    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    /// Returns `true` if this is the zero polynomial. Constant-time in the limbs.
    pub fn is_zero(&self) -> bool {
        equal_to_zero(&self.limbs) != 0
    }

    /// Returns `true` if this is the polynomial `1`. Constant-time in the limbs.
    pub fn is_one(&self) -> bool {
        equal_to_one(&self.limbs) != 0
    }

    /// Constant-time equality: the running cost is independent of the limb values,
    /// so this is safe on secret-bearing polynomials (unlike the derived `==`,
    /// which short-circuits). Both operands must have the same limb count.
    pub fn ct_eq(&self, other: &BinaryPoly) -> bool {
        equal_to(&self.limbs, &other.limbs) != 0
    }

    /// **Variable-time** bit length: most-significant set bit position plus one
    /// (degree + 1), or `0` for the zero polynomial. The `_var` timing is
    /// data-dependent — do not use where the polynomial is secret and observable.
    pub fn bit_length(&self) -> usize {
        bit_length_var(&self.limbs)
    }
}

/// Polynomial addition over `GF(2)` (limb-wise XOR). No reduction needed: a
/// degree-`< n` sum of degree-`< n` inputs stays degree-`< n`. Both operands must
/// have the same limb count.
impl Add for &BinaryPoly {
    type Output = BinaryPoly;

    fn add(self, rhs: &BinaryPoly) -> BinaryPoly {
        debug_assert_eq!(self.limbs.len(), rhs.limbs.len());
        let mut out = vec![0u64; self.limbs.len()];
        add(&self.limbs, &rhs.limbs, &mut out);
        BinaryPoly { limbs: out.into_boxed_slice() }
    }
}

/// In-place polynomial addition (`self += rhs`, limb-wise XOR).
impl AddAssign<&BinaryPoly> for BinaryPoly {
    fn add_assign(&mut self, rhs: &BinaryPoly) {
        debug_assert_eq!(self.limbs.len(), rhs.limbs.len());
        add_to(&rhs.limbs, &mut self.limbs);
    }
}

// --- slice-level primitives（crate 內部：BinaryPoly 方法與 operator/kernel 層共用） ---

/// `z = x + y`（limb-wise XOR）。三者長度須相同。
pub(crate) fn add(x: &[u64], y: &[u64], z: &mut [u64]) {
    debug_assert!(x.len() == y.len() && y.len() == z.len());
    for i in 0..z.len() {
        z[i] = x[i] ^ y[i];
    }
}

/// `z += x`（把 x XOR 進累加器 z）。兩者長度須相同。
pub(crate) fn add_to(x: &[u64], z: &mut [u64]) {
    debug_assert!(x.len() == z.len());
    for i in 0..z.len() {
        z[i] ^= x[i];
    }
}

/// 常數時間相等：`x == y` → `u64::MAX`，否則 `0`。跨 limb 的 OR 讓成本與資料無關。
pub(crate) fn equal_to(x: &[u64], y: &[u64]) -> u64 {
    debug_assert!(x.len() == y.len());
    let mut d = 0u64;
    for i in 0..x.len() {
        d |= x[i] ^ y[i];
    }
    is_zero_mask(d)
}

/// 常數時間測試乘法單位元 `1`：是 → `u64::MAX`，否則 `0`。
pub(crate) fn equal_to_one(x: &[u64]) -> u64 {
    let mut d = x.first().map_or(1, |&w| w ^ 1); // 空切片 → 非 1
    for &w in x.iter().skip(1) {
        d |= w;
    }
    is_zero_mask(d)
}

/// 常數時間測試零多項式：全零 → `u64::MAX`，否則 `0`。
pub(crate) fn equal_to_zero(x: &[u64]) -> u64 {
    let mut d = 0u64;
    for &w in x {
        d |= w;
    }
    is_zero_mask(d)
}

/// **變動時間**位元長度：最高設定位元位置 + 1（degree + 1），零多項式為 `0`。
pub(crate) fn bit_length_var(x: &[u64]) -> usize {
    for i in (0..x.len()).rev() {
        let x_i = x[i];
        if x_i != 0 {
            return i * 64 + (64 - x_i.leading_zeros() as usize);
        }
    }
    0
}

/// 由差異累積值 `d` 得常數時間遮罩：`d == 0` → `u64::MAX`，否則 `0`（無分支）。
fn is_zero_mask(d: u64) -> u64 {
    ((d | d.wrapping_neg()) >> 63).wrapping_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_rounds_up_to_limbs() {
        assert_eq!(size(0), 0);
        assert_eq!(size(1), 1);
        assert_eq!(size(64), 1);
        assert_eq!(size(65), 2);
        assert_eq!(size(163), 3); // sect163*
        assert_eq!(size(233), 4);
    }

    #[test]
    fn zero_and_one_constructors() {
        assert!(BinaryPoly::zero(3).is_zero());
        assert!(!BinaryPoly::zero(3).is_one());
        assert!(BinaryPoly::one(3).is_one());
        assert!(!BinaryPoly::one(3).is_zero());
        assert_eq!(BinaryPoly::one(3).limbs(), &[1, 0, 0]);
    }

    #[test]
    fn add_is_xor_and_self_inverse() {
        let x = BinaryPoly::from_limbs([0b1011u64, 0xFFFF_0000_FFFF_0000]);
        let y = BinaryPoly::from_limbs([0b0110u64, 0x0000_FFFF_0000_FFFF]);
        assert_eq!((&x + &y).limbs(), &[0b1101, 0xFFFF_FFFF_FFFF_FFFF]);
        // 二元體：x + x = 0
        assert!((&x + &x).is_zero());
    }

    #[test]
    fn add_assign_accumulates() {
        let mut z = BinaryPoly::from_limbs([0b1010u64, 0]);
        z += &BinaryPoly::from_limbs([0b0110u64, 0]);
        assert_eq!(z.limbs(), &[0b1100, 0]);
    }

    #[test]
    fn ct_eq_matches_value() {
        let a = BinaryPoly::from_limbs([1u64, 2, 3]);
        let b = BinaryPoly::from_limbs([1u64, 2, 3]);
        let c = BinaryPoly::from_limbs([1u64, 2, 4]);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert_eq!(a, b); // 派生的結構相等亦一致
        assert_ne!(a, c);
    }

    #[test]
    fn bit_length_finds_top_bit() {
        assert_eq!(BinaryPoly::zero(2).bit_length(), 0);
        assert_eq!(BinaryPoly::from_limbs([1u64, 0]).bit_length(), 1);
        assert_eq!(BinaryPoly::from_limbs([0b1000u64, 0]).bit_length(), 4);
        assert_eq!(BinaryPoly::from_limbs([0u64, 1]).bit_length(), 65);
        assert_eq!(BinaryPoly::from_limbs([5u64, 0x8000_0000_0000_0000]).bit_length(), 128);
    }

    #[test]
    fn primitive_masks() {
        assert_eq!(equal_to_zero(&[0u64, 0]), u64::MAX);
        assert_eq!(equal_to_zero(&[0u64, 1]), 0);
        assert_eq!(equal_to_one(&[1u64, 0]), u64::MAX);
        assert_eq!(equal_to_one(&[1u64, 1]), 0);
        assert_eq!(equal_to(&[1u64, 2], &[1u64, 2]), u64::MAX);
        assert_eq!(equal_to(&[1u64, 2], &[1u64, 3]), 0);
    }
}
