//! SEC binary fields 的固定寬度共用核心。
//!
//! 每個欄位以型別層級的 `(m, k1, k2, k3)` 綁定約簡多項式；元素本體只保留
//! 精確寬度的 `[u64; N]`。乘法、平方與約簡因而可被單態化，不需要 reducer
//! enum 分派；`BinPolyMultiplier` 僅為了符合既有 `BinaryPolyOps` 介面而保留。

use core::fmt;
use core::marker::PhantomData;
use core::ops::Add;

use tc_binpoly::interleave::{
    expand64_to128_into, unshuffle_pair_to_even_odd, unshuffle_to_even_odd,
};
use tc_binpoly::scalar::impl_mul;
use tc_binpoly::{BinPolyError, BinPolyMultiplier, BinaryPolyOps, FixedBinaryPoly, equal_to_zero};
use tc_f2m_curve::F2mPolynomial;

/// 編譯期固定的二元體約簡多項式。
#[doc(hidden)]
pub trait BinaryFieldSpec<const N: usize>: 'static {
    const M: usize;
    const K1: usize;
    const K2: usize;
    const K3: usize;
    /// `sqrt(x)` 中奇數次方部分要乘上的 `sqrt(z)`。
    const ROOT_Z: [u64; N];
}

/// 一個欄位的靜態運算入口；具名 `SecT*Field` 是此型別的 alias。
#[doc(hidden)]
pub struct SpecializedBinaryField<S, const N: usize>(PhantomData<S>);

impl<S: BinaryFieldSpec<N>, const N: usize> SpecializedBinaryField<S, N> {
    fn multiplier() -> BinPolyMultiplier {
        if S::K2 == 0 && S::K3 == 0 {
            BinPolyMultiplier::trinomial(S::M, S::K1).expect("SEC trinomial parameters are valid")
        } else {
            BinPolyMultiplier::pentanomial(S::M, S::K1, S::K2, S::K3)
                .expect("SEC pentanomial parameters are valid")
        }
    }

    fn validate_multiplier(multiplier: &BinPolyMultiplier) -> Result<(), BinPolyError> {
        let expected = Self::multiplier();
        if multiplier != &expected {
            return Err(BinPolyError::MismatchedModulus);
        }
        Ok(())
    }

    /// 固定寬度 carryless 乘法與欄位約簡。
    pub fn multiply(x: &[u64; N], y: &[u64; N]) -> [u64; N] {
        let mut wide = [[0_u64; N]; 2];
        impl_mul(x, y, wide.as_flattened_mut());
        Self::reduce(wide.as_flattened_mut())
    }

    /// 以位元交錯展開平方，再做欄位約簡。
    pub fn square(x: &[u64; N]) -> [u64; N] {
        let mut wide = [[0_u64; N]; 2];
        expand64_to128_into(x, wide.as_flattened_mut());
        Self::reduce(wide.as_flattened_mut())
    }

    /// 連續平方。
    pub fn square_pow(mut x: [u64; N], count: usize) -> [u64; N] {
        for _ in 0..count {
            x = Self::square(&x);
        }
        x
    }

    /// 以現有 Itoh-Tsujii 核心求反元素；此路徑仍然完全使用 stack scratch。
    pub fn invert(multiplier: BinPolyMultiplier, x: [u64; N]) -> Result<[u64; N], BinPolyError> {
        FixedBinaryPoly::from_limbs(multiplier, x)?
            .invert()
            .map(FixedBinaryPoly::into_limbs)
    }

    /// 二元體平方根。先把偶數與奇數次方拆開，再乘一次固定的
    /// `sqrt(z)`；相較通用 Frobenius 路徑不需要 `m - 1` 次平方。
    pub fn sqrt(x: [u64; N]) -> [u64; N] {
        let mut even = [0_u64; N];
        let mut odd = [0_u64; N];
        let mut input = 0;
        let mut output = 0;
        while input + 1 < N {
            (even[output], odd[output]) = unshuffle_pair_to_even_odd(x[input], x[input + 1]);
            input += 2;
            output += 1;
        }
        if input < N {
            (even[output], odd[output]) = unshuffle_to_even_odd(x[input]);
        }

        let odd_root = Self::multiply(&odd, &S::ROOT_Z);
        for (left, right) in even.iter_mut().zip(odd_root) {
            *left ^= right;
        }
        even
    }

    fn reduce(wide: &mut [u64]) -> [u64; N] {
        debug_assert_eq!(wide.len(), N * 2);
        debug_assert_ne!(S::M & 63, 0);
        debug_assert!(S::M - S::K3.max(S::K1) >= 64);
        if S::K2 != 0 {
            return Self::reduce_pentanomial_low(wide);
        }
        if S::K1 < 64 {
            Self::reduce_trinomial_low(wide)
        } else {
            Self::reduce_trinomial_high(wide)
        }
    }

    fn reduce_trinomial_low(wide: &mut [u64]) -> [u64; N] {
        let shift_m = S::M & 63;
        let shift_k = S::K1;
        for position in (0..N).rev() {
            let high = (wide[position + N - 1] >> shift_m) | (wide[position + N] << (64 - shift_m));
            wide[position] ^= high ^ (high << shift_k);
            wide[position + 1] ^= high >> (64 - shift_k);
        }
        Self::copy_reduced(wide)
    }

    fn reduce_trinomial_high(wide: &mut [u64]) -> [u64; N] {
        let shift_m = S::M & 63;
        let word_k = S::K1 >> 6;
        let shift_k = S::K1 & 63;
        for position in (0..N).rev() {
            let high = (wide[position + N - 1] >> shift_m) | (wide[position + N] << (64 - shift_m));
            wide[position] ^= high;
            wide[position + word_k] ^= high << shift_k;
            wide[position + word_k + 1] ^= high >> (64 - shift_k);
        }
        Self::copy_reduced(wide)
    }

    fn reduce_pentanomial_low(wide: &mut [u64]) -> [u64; N] {
        debug_assert!(S::K3 < 64);
        let shift_m = S::M & 63;
        for position in (0..N).rev() {
            let high = (wide[position + N - 1] >> shift_m) | (wide[position + N] << (64 - shift_m));
            wide[position] ^= high ^ (high << S::K1) ^ (high << S::K2) ^ (high << S::K3);
            wide[position + 1] ^=
                (high >> (64 - S::K1)) ^ (high >> (64 - S::K2)) ^ (high >> (64 - S::K3));
        }
        Self::copy_reduced(wide)
    }

    fn copy_reduced(wide: &[u64]) -> [u64; N] {
        let mut output = [0_u64; N];
        output.copy_from_slice(&wide[..N]);
        output[N - 1] &= (1_u64 << (S::M & 63)) - 1;
        output
    }

    /// 逐位元定義式約簡，只在測試中作為 word kernel 的獨立 oracle。
    #[cfg(test)]
    pub(crate) fn multiply_reference(x: &[u64; N], y: &[u64; N]) -> [u64; N] {
        let mut storage = [[0_u64; N]; 2];
        let wide = storage.as_flattened_mut();
        impl_mul(x, y, wide);
        let mut bit = wide.len() * 64;
        while bit > S::M {
            bit -= 1;
            if !test_bit(wide, bit) {
                continue;
            }
            toggle_bit(wide, bit);
            let offset = bit - S::M;
            toggle_bit(wide, offset);
            toggle_bit(wide, offset + S::K1);
            if S::K2 != 0 {
                toggle_bit(wide, offset + S::K2);
                toggle_bit(wide, offset + S::K3);
            }
        }

        let mut output = [0_u64; N];
        output.copy_from_slice(&wide[..N]);
        let top_bits = S::M & 63;
        if top_bits != 0 {
            output[N - 1] &= (1_u64 << top_bits) - 1;
        }
        output
    }
}

#[inline]
#[cfg(test)]
fn test_bit(words: &[u64], bit: usize) -> bool {
    words[bit >> 6] & (1_u64 << (bit & 63)) != 0
}

#[inline]
#[cfg(test)]
fn toggle_bit(words: &mut [u64], bit: usize) {
    words[bit >> 6] ^= 1_u64 << (bit & 63);
}

/// 固定欄位的 polynomial-basis 值。
#[doc(hidden)]
pub struct SpecializedBinaryPoly<S, const N: usize> {
    multiplier: BinPolyMultiplier,
    limbs: [u64; N],
    marker: PhantomData<S>,
}

impl<S, const N: usize> Clone for SpecializedBinaryPoly<S, N> {
    fn clone(&self) -> Self {
        Self {
            multiplier: self.multiplier.clone(),
            limbs: self.limbs,
            marker: PhantomData,
        }
    }
}

impl<S, const N: usize> PartialEq for SpecializedBinaryPoly<S, N> {
    fn eq(&self, other: &Self) -> bool {
        self.multiplier == other.multiplier && self.limbs == other.limbs
    }
}

impl<S, const N: usize> Eq for SpecializedBinaryPoly<S, N> {}

impl<S, const N: usize> fmt::Debug for SpecializedBinaryPoly<S, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SpecializedBinaryPoly")
            .field(&self.limbs)
            .finish()
    }
}

impl<S: BinaryFieldSpec<N>, const N: usize> BinaryPolyOps for SpecializedBinaryPoly<S, N> {
    fn zero(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
        SpecializedBinaryField::<S, N>::validate_multiplier(&multiplier)?;
        Ok(Self {
            multiplier,
            limbs: [0; N],
            marker: PhantomData,
        })
    }

    fn one(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
        let mut value = Self::zero(multiplier)?;
        value.limbs[0] = 1;
        Ok(value)
    }

    fn multiplier(&self) -> &BinPolyMultiplier {
        &self.multiplier
    }

    fn as_limbs(&self) -> &[u64] {
        &self.limbs
    }

    fn multiply(&self, rhs: &Self) -> Result<Self, BinPolyError> {
        if self.multiplier != rhs.multiplier {
            return Err(BinPolyError::MismatchedModulus);
        }
        Ok(Self {
            multiplier: self.multiplier.clone(),
            limbs: SpecializedBinaryField::<S, N>::multiply(&self.limbs, &rhs.limbs),
            marker: PhantomData,
        })
    }

    fn square(&self) -> Self {
        Self {
            multiplier: self.multiplier.clone(),
            limbs: SpecializedBinaryField::<S, N>::square(&self.limbs),
            marker: PhantomData,
        }
    }

    fn square_pow(&self, count: usize) -> Self {
        Self {
            multiplier: self.multiplier.clone(),
            limbs: SpecializedBinaryField::<S, N>::square_pow(self.limbs, count),
            marker: PhantomData,
        }
    }

    fn invert(&self) -> Result<Self, BinPolyError> {
        Ok(Self {
            multiplier: self.multiplier.clone(),
            limbs: SpecializedBinaryField::<S, N>::invert(self.multiplier.clone(), self.limbs)?,
            marker: PhantomData,
        })
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<S: BinaryFieldSpec<N>, const N: usize> Add<&SpecializedBinaryPoly<S, N>>
    for SpecializedBinaryPoly<S, N>
{
    type Output = SpecializedBinaryPoly<S, N>;

    fn add(mut self, rhs: &SpecializedBinaryPoly<S, N>) -> Self::Output {
        assert_eq!(self.multiplier, rhs.multiplier, "binary fields differ");
        for (left, right) in self.limbs.iter_mut().zip(rhs.limbs) {
            *left ^= right;
        }
        self
    }
}

impl<S: BinaryFieldSpec<N>, const N: usize> F2mPolynomial for SpecializedBinaryPoly<S, N> {
    fn from_limb_slice(multiplier: BinPolyMultiplier, limbs: &[u64]) -> Result<Self, BinPolyError> {
        SpecializedBinaryField::<S, N>::validate_multiplier(&multiplier)?;
        let limbs: [u64; N] = limbs.try_into().map_err(|_| BinPolyError::InvalidLength {
            expected: N,
            actual: limbs.len(),
        })?;
        let top_bits = S::M & 63;
        if top_bits != 0 && limbs[N - 1] >> top_bits != 0 {
            return Err(BinPolyError::UnreducedValue);
        }
        Ok(Self {
            multiplier,
            limbs,
            marker: PhantomData,
        })
    }

    fn sqrt(&self) -> Self {
        SpecializedBinaryPoly::sqrt(self)
    }
}

impl<S: BinaryFieldSpec<N>, const N: usize> SpecializedBinaryPoly<S, N> {
    /// 特化平方根核心，供欄位元素測試與後續融合公式使用。
    pub fn sqrt(&self) -> Self {
        if equal_to_zero(&self.limbs) == u64::MAX {
            return self.clone();
        }
        Self {
            multiplier: self.multiplier.clone(),
            limbs: SpecializedBinaryField::<S, N>::sqrt(self.limbs),
            marker: PhantomData,
        }
    }
}
