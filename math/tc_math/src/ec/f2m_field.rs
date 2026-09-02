//! Binary-field definition shared by every element of a `GF(2ᵐ)` curve field.
//!
//! Corresponds to `F2mFieldData` in Bouncy Castle C#: the immutable per-field data
//! — the degree `m`, the reduction polynomial, and the [`BinPolyMul`] /
//! [`BinPolyInv`] operators built from them. Every [`F2mFieldElement`] holds an
//! `Arc<F2mField>` so a whole curve's worth of elements share one copy.
//!
//! [`F2mFieldElement`]: super::F2mFieldElement

use alloc::boxed::Box;

use crate::binpoly::{
    self, BinPolyInv, BinPolyMul, create_binpoly_mul_pentanomial, create_binpoly_mul_trinomial,
    size,
};

/// The shape of the reduction polynomial (polynomial-basis representation). Modelling
/// it as an enum makes "trinomial **or** pentanomial" the only representable choice —
/// an invalid tap count (2, 4, …) cannot exist, unlike bc's `int[] ks`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) enum ReductionPolynomial {
    /// `xᵐ + xᵏ¹ + 1`.
    Trinomial { k1: usize },
    /// `xᵐ + xᵏ³ + xᵏ² + xᵏ¹ + 1`.
    Pentanomial { k1: usize, k2: usize, k3: usize },
}

/// The shared definition of a binary field `GF(2ᵐ) = GF(2)[x] / r(x)` in polynomial
/// basis, where `r(x)` is the [`ReductionPolynomial`].
///
/// Mirrors bc `F2mFieldData`. Holds two multiply operators: `mul` for the field's
/// own `Multiply`/`Square`, and a second one owned by `inv` (Itoh–Tsujii wraps a
/// multiplier). bc shares one operator by reference; our factory takes ownership, so
/// we build two — the operators are stateless, so two instances behave identically.
pub(crate) struct F2mField {
    // 體域度數 m（= 約簡多項式的最高次數）。
    m: usize,
    // 約簡多項式的形狀（三項式 / 五項式）。
    reduction: ReductionPolynomial,
    // 乘法 operator（供 multiply/square/square_n）。
    mul: Box<dyn BinPolyMul>,
    // 反元素 operator（Itoh–Tsujii，內部另持一個 mul）。
    inv: Box<dyn BinPolyInv>,
}

impl F2mField {
    /// Builds the field `GF(2ᵐ)` reduced by the trinomial `xᵐ + xᵏ¹ + 1`.
    pub fn trinomial(m: usize, k1: usize) -> Self {
        Self::new(m, ReductionPolynomial::Trinomial { k1 })
    }

    /// Builds the field `GF(2ᵐ)` reduced by the pentanomial
    /// `xᵐ + xᵏ³ + xᵏ² + xᵏ¹ + 1`.
    pub fn pentanomial(m: usize, k1: usize, k2: usize, k3: usize) -> Self {
        Self::new(m, ReductionPolynomial::Pentanomial { k1, k2, k3 })
    }

    /// Core constructor mirroring bc `F2mFieldData.From`: builds the multiplier for
    /// the reduction polynomial, then wraps a second multiplier in an Itoh–Tsujii
    /// inverter.
    fn new(m: usize, reduction: ReductionPolynomial) -> Self {
        let mul = build_mul(m, &reduction);
        let inv = binpoly::create(build_mul(m, &reduction));
        F2mField { m, reduction, mul, inv }
    }

    /// The field degree `m`.
    pub fn m(&self) -> usize {
        self.m
    }

    /// Number of `u64` limbs a field element of this field occupies (`⌈m / 64⌉`).
    pub fn size(&self) -> usize {
        size(self.m)
    }

    /// First reduction tap `k1`.
    pub fn k1(&self) -> usize {
        match self.reduction {
            ReductionPolynomial::Trinomial { k1 }
            | ReductionPolynomial::Pentanomial { k1, .. } => k1,
        }
    }

    /// Second reduction tap `k2`, or `0` for a trinomial (bc convention).
    pub fn k2(&self) -> usize {
        match self.reduction {
            ReductionPolynomial::Pentanomial { k2, .. } => k2,
            _ => 0,
        }
    }

    /// Third reduction tap `k3`, or `0` for a trinomial (bc convention).
    pub fn k3(&self) -> usize {
        match self.reduction {
            ReductionPolynomial::Pentanomial { k3, .. } => k3,
            _ => 0,
        }
    }

    /// The multiply operator (for `multiply`/`square`/`square_n`).
    pub fn mul(&self) -> &dyn BinPolyMul {
        &*self.mul
    }

    /// The inverse operator (Itoh–Tsujii).
    pub fn inv(&self) -> &dyn BinPolyInv {
        &*self.inv
    }
}

/// Builds the multiply operator for the given degree and reduction polynomial. The
/// enum is exhaustive, so no invalid-shape fallback is needed.
fn build_mul(m: usize, reduction: &ReductionPolynomial) -> Box<dyn BinPolyMul> {
    match *reduction {
        ReductionPolynomial::Trinomial { k1 } => create_binpoly_mul_trinomial(m, k1),
        ReductionPolynomial::Pentanomial { k1, k2, k3 } => {
            create_binpoly_mul_pentanomial(m, k1, k2, k3)
        }
    }
}

/// Two fields are equal iff they share the same degree and the same reduction
/// polynomial.
///
/// Corresponds to bc `F2mFieldData.Equals`. The `mul`/`inv` operators are derived
/// from `m` and the reduction polynomial, so they are not compared.
impl PartialEq for F2mField {
    fn eq(&self, other: &Self) -> bool {
        self.m == other.m && self.reduction == other.reduction
    }
}

impl Eq for F2mField {}

/// Hashes the degree and reduction polynomial (matching [`PartialEq`]).
///
/// Corresponds to bc `F2mFieldData.GetHashCode`.
impl core::hash::Hash for F2mField {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.m.hash(state);
        self.reduction.hash(state);
    }
}

impl core::fmt::Debug for F2mField {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("F2mField")
            .field("m", &self.m)
            .field("reduction", &self.reduction)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trinomial_field_reports_shape() {
        // sect233r1：GF(2^233)，x^233 + x^74 + 1。
        let f = F2mField::trinomial(233, 74);
        assert_eq!(f.m(), 233);
        assert_eq!(f.size(), 4); // ⌈233/64⌉
        assert_eq!(f.k1(), 74);
        assert_eq!(f.k2(), 0); // 三項式 → k2/k3 為 0
        assert_eq!(f.k3(), 0);
        assert_eq!(f.mul().n(), 233);
        assert_eq!(f.inv().n(), 233);
    }

    #[test]
    fn pentanomial_field_reports_shape() {
        // sect163k1：GF(2^163)，x^163 + x^7 + x^6 + x^3 + 1。
        let f = F2mField::pentanomial(163, 3, 6, 7);
        assert_eq!(f.m(), 163);
        assert_eq!(f.size(), 3);
        assert_eq!(f.k1(), 3);
        assert_eq!(f.k2(), 6);
        assert_eq!(f.k3(), 7);
    }

    #[test]
    fn equality_compares_shape_only() {
        let a = F2mField::trinomial(233, 74);
        let b = F2mField::trinomial(233, 74);
        let c = F2mField::trinomial(409, 87);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // 三項式 vs 五項式 → 不相等。
        assert_ne!(F2mField::trinomial(163, 7), F2mField::pentanomial(163, 3, 6, 7));
    }
}
