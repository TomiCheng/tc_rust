use alloc::vec;

use crate::MAX_N;
use crate::error::BinPolyError;
use crate::ops::{clear, size};
use crate::reduce::{Reduce, Reducer};
use crate::scalar;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use tc_runtime::intrinsics::x86::Pclmulqdq;

/// Extended scratch sizes at or below this many limbs stay on the stack.
pub const STACK_ALLOC_CUTOFF: usize = 128;

/// Binary-polynomial multiplication and squaring modulo a fixed polynomial.
pub trait BinPolyMul {
    /// Polynomial bit length.
    fn n(&self) -> usize;

    /// Number of limbs in a reduced value.
    fn size(&self) -> usize;

    /// Computes `z = x * y mod r(x)`.
    fn multiply(&self, x: &[u64], y: &[u64], z: &mut [u64]);

    /// Computes `z = x^2 mod r(x)`.
    fn square(&self, x: &[u64], z: &mut [u64]);

    /// Computes `z = x^(2^count) mod r(x)`.
    fn square_n(&self, x: &[u64], count: usize, z: &mut [u64]);
}

/// Shared scalar multiplier state and default squaring implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinPolyMulBase {
    n: usize,
    size: usize,
    size_ext: usize,
    reducer: Reducer,
}

impl BinPolyMulBase {
    fn new(n: usize, reducer: Reducer) -> Self {
        let size = size(n);
        Self {
            n,
            size,
            size_ext: size * 2,
            reducer,
        }
    }

    fn multiply_medium(&self, x: &[u64], y: &[u64], z: &mut [u64]) {
        self.check_value(x);
        self.check_value(y);
        self.check_output(z);

        if self.size_ext <= STACK_ALLOC_CUTOFF {
            let mut buffer = [0_u64; STACK_ALLOC_CUTOFF];
            let mut scratch = ClearOnDrop::new(&mut buffer[..self.size_ext]);
            scalar::impl_mul(x, y, scratch.as_mut());
            self.reducer.reduce(scratch.as_mut(), z);
        } else {
            let mut buffer = vec![0_u64; self.size_ext];
            let mut scratch = ClearOnDrop::new(&mut buffer);
            scalar::impl_mul(x, y, scratch.as_mut());
            self.reducer.reduce(scratch.as_mut(), z);
        }
    }

    fn multiply_large(&self, x: &[u64], y: &[u64], z: &mut [u64]) {
        self.check_value(x);
        self.check_value(y);
        self.check_output(z);

        let karatsuba_scratch = scalar::karatsuba_scratch_size(self.size);
        let total = self.size_ext + karatsuba_scratch;
        if total <= STACK_ALLOC_CUTOFF {
            let mut buffer = [0_u64; STACK_ALLOC_CUTOFF];
            let mut combined = ClearOnDrop::new(&mut buffer[..total]);
            let (tt, scratch) = combined.as_mut().split_at_mut(self.size_ext);
            scalar::impl_karatsuba(x, y, tt, scratch);
            self.reducer.reduce(tt, z);
        } else {
            let mut buffer = vec![0_u64; total];
            let mut combined = ClearOnDrop::new(&mut buffer);
            let (tt, scratch) = combined.as_mut().split_at_mut(self.size_ext);
            scalar::impl_karatsuba(x, y, tt, scratch);
            self.reducer.reduce(tt, z);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn multiply_x86_medium(&self, proof: Pclmulqdq, x: &[u64], y: &[u64], z: &mut [u64]) {
        self.check_value(x);
        self.check_value(y);
        self.check_output(z);

        if self.size_ext <= STACK_ALLOC_CUTOFF {
            let mut buffer = [0_u64; STACK_ALLOC_CUTOFF];
            let mut scratch = ClearOnDrop::new(&mut buffer[..self.size_ext]);
            crate::x86::impl_mul(proof, x, y, scratch.as_mut());
            self.reducer.reduce(scratch.as_mut(), z);
        } else {
            let mut buffer = vec![0_u64; self.size_ext];
            let mut scratch = ClearOnDrop::new(&mut buffer);
            crate::x86::impl_mul(proof, x, y, scratch.as_mut());
            self.reducer.reduce(scratch.as_mut(), z);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn multiply_x86_large(&self, proof: Pclmulqdq, x: &[u64], y: &[u64], z: &mut [u64]) {
        self.check_value(x);
        self.check_value(y);
        self.check_output(z);

        let karatsuba_scratch = crate::x86::karatsuba_scratch_size(self.size);
        let total = self.size_ext + karatsuba_scratch;
        if total <= STACK_ALLOC_CUTOFF {
            let mut buffer = [0_u64; STACK_ALLOC_CUTOFF];
            let mut combined = ClearOnDrop::new(&mut buffer[..total]);
            let (tt, scratch) = combined.as_mut().split_at_mut(self.size_ext);
            crate::x86::impl_karatsuba(proof, x, y, tt, scratch);
            self.reducer.reduce(tt, z);
        } else {
            let mut buffer = vec![0_u64; total];
            let mut combined = ClearOnDrop::new(&mut buffer);
            let (tt, scratch) = combined.as_mut().split_at_mut(self.size_ext);
            crate::x86::impl_karatsuba(proof, x, y, tt, scratch);
            self.reducer.reduce(tt, z);
        }
    }

    fn square(&self, x: &[u64], z: &mut [u64]) {
        self.check_value(x);
        self.check_output(z);

        if self.size_ext <= STACK_ALLOC_CUTOFF {
            let mut buffer = [0_u64; STACK_ALLOC_CUTOFF];
            let mut scratch = ClearOnDrop::new(&mut buffer[..self.size_ext]);
            expand_square(x, scratch.as_mut());
            self.reducer.reduce(scratch.as_mut(), z);
        } else {
            let mut buffer = vec![0_u64; self.size_ext];
            let mut scratch = ClearOnDrop::new(&mut buffer);
            expand_square(x, scratch.as_mut());
            self.reducer.reduce(scratch.as_mut(), z);
        }
    }

    fn square_n(&self, x: &[u64], count: usize, z: &mut [u64]) {
        assert!(count > 0, "square count must be positive");
        self.check_value(x);
        self.check_output(z);

        if self.size <= STACK_ALLOC_CUTOFF {
            let mut buffer = [0_u64; STACK_ALLOC_CUTOFF];
            let mut current = ClearOnDrop::new(&mut buffer[..self.size]);
            current.as_mut().copy_from_slice(x);
            self.square_n_with_current(&mut current, count, z);
        } else {
            let mut buffer = vec![0_u64; self.size];
            let mut current = ClearOnDrop::new(&mut buffer);
            current.as_mut().copy_from_slice(x);
            self.square_n_with_current(&mut current, count, z);
        }
    }

    fn square_n_with_current(&self, current: &mut ClearOnDrop<'_>, count: usize, z: &mut [u64]) {
        for round in 0..count {
            self.square(current.as_ref(), z);
            if round + 1 < count {
                current.as_mut().copy_from_slice(z);
            }
        }
    }

    fn check_value(&self, value: &[u64]) {
        assert_eq!(value.len(), self.size, "invalid polynomial input length");
        debug_assert_reduced(self.n, value);
    }

    fn check_output(&self, output: &[u64]) {
        assert_eq!(output.len(), self.size, "invalid polynomial output length");
    }

    pub(crate) const fn is_binomial(&self) -> bool {
        self.reducer.is_binomial()
    }

    fn multiply_fixed<const N: usize>(&self, x: &[u64; N], y: &[u64; N], z: &mut [u64; N]) {
        assert_eq!(
            N, self.size,
            "fixed polynomial width does not match modulus"
        );
        debug_assert_reduced(self.n, x);
        debug_assert_reduced(self.n, y);
        let mut tt = FixedExtendedScratch([[0_u64; N]; 2]);
        scalar::impl_mul(x, y, tt.as_mut());
        self.reducer.reduce(tt.as_mut(), z);
    }

    fn square_fixed<const N: usize>(&self, x: &[u64; N], z: &mut [u64; N]) {
        assert_eq!(
            N, self.size,
            "fixed polynomial width does not match modulus"
        );
        debug_assert_reduced(self.n, x);
        let mut tt = FixedExtendedScratch([[0_u64; N]; 2]);
        expand_square(x, tt.as_mut());
        self.reducer.reduce(tt.as_mut(), z);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn multiply_fixed_x86<const N: usize>(
        &self,
        proof: Pclmulqdq,
        x: &[u64; N],
        y: &[u64; N],
        z: &mut [u64; N],
    ) {
        assert_eq!(
            N, self.size,
            "fixed polynomial width does not match modulus"
        );
        debug_assert_reduced(self.n, x);
        debug_assert_reduced(self.n, y);
        let mut tt = FixedExtendedScratch([[0_u64; N]; 2]);
        crate::x86::impl_mul(proof, x, y, tt.as_mut());
        self.reducer.reduce(tt.as_mut(), z);
    }
}

/// Statically dispatched multiplier backend.
///
/// Keeping the backend as an enum makes scalar Medium/Large and x86-v128
/// selection a construction-time choice rather than a per-operation feature
/// test or a `Box<dyn BinPolyMul>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BinPolyMultiplier {
    /// Portable scalar table-based multiplication.
    ScalarMedium(BinPolyMulBase),
    /// Portable scalar Karatsuba multiplication with table-based leaves.
    ScalarLarge(BinPolyMulBase),
    /// PCLMULQDQ backend selected once at construction.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    X86V128Medium {
        base: BinPolyMulBase,
        proof: Pclmulqdq,
    },
    /// PCLMULQDQ Karatsuba backend selected once at construction.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    X86V128Large {
        base: BinPolyMulBase,
        proof: Pclmulqdq,
    },
}

impl BinPolyMultiplier {
    /// Creates multiplication modulo `x^n + 1`.
    ///
    /// This quotient is a ring, not a field: `x^n + 1` is reducible and this
    /// multiplier must not be passed to an inversion constructor.
    pub fn binomial(n: usize) -> Result<Self, BinPolyError> {
        validate_degree(n, 1)?;
        Ok(Self::scalar(n, Reducer::binomial(n)))
    }

    /// Creates multiplication modulo `x^n + x^k + 1`.
    pub fn trinomial(n: usize, k: usize) -> Result<Self, BinPolyError> {
        validate_degree(n, 3)?;
        if k == 0 || k >= n {
            return Err(BinPolyError::InvalidTrinomialTap { n, k });
        }
        Ok(Self::scalar(n, Reducer::trinomial(n, k)))
    }

    /// Creates multiplication modulo
    /// `x^n + x^k3 + x^k2 + x^k1 + 1`.
    pub fn pentanomial(n: usize, k1: usize, k2: usize, k3: usize) -> Result<Self, BinPolyError> {
        validate_degree(n, 5)?;
        if k1 == 0 || k2 <= k1 || k3 <= k2 || k3 >= n {
            return Err(BinPolyError::InvalidPentanomialTaps { n, k1, k2, k3 });
        }
        Ok(Self::scalar(n, Reducer::pentanomial(n, k1, k2, k3)))
    }

    fn scalar(n: usize, reducer: Reducer) -> Self {
        let base = BinPolyMulBase::new(n, reducer);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if let Some(proof) = Pclmulqdq::detect() {
            return if base.size < crate::x86::KARATSUBA_CUTOFF {
                Self::X86V128Medium { base, proof }
            } else {
                Self::X86V128Large { base, proof }
            };
        }
        if base.size < scalar::KARATSUBA_CUTOFF {
            Self::ScalarMedium(base)
        } else {
            Self::ScalarLarge(base)
        }
    }

    fn base(&self) -> &BinPolyMulBase {
        match self {
            Self::ScalarMedium(base) | Self::ScalarLarge(base) => base,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::X86V128Medium { base, .. } | Self::X86V128Large { base, .. } => base,
        }
    }

    pub(crate) const fn is_binomial(&self) -> bool {
        match self {
            Self::ScalarMedium(base) | Self::ScalarLarge(base) => base.is_binomial(),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::X86V128Medium { base, .. } | Self::X86V128Large { base, .. } => {
                base.is_binomial()
            }
        }
    }

    /// Reduces a disposable double-width product into one field/ring value.
    ///
    /// This low-level entry point supports reducer benchmarking and callers
    /// that already have a carryless extended product. `tt` must contain
    /// exactly `2 * self.size()` limbs and no coefficient above degree
    /// `2 * self.n() - 2`; its contents are arbitrary after the call.
    pub fn reduce_extended(&self, tt: &mut [u64], z: &mut [u64]) {
        let base = self.base();
        assert_eq!(tt.len(), base.size_ext, "invalid extended input length");
        base.check_output(z);
        base.reducer.reduce(tt, z);
    }

    pub(crate) fn multiply_fixed<const N: usize>(
        &self,
        x: &[u64; N],
        y: &[u64; N],
        z: &mut [u64; N],
    ) {
        match self {
            Self::ScalarMedium(base) | Self::ScalarLarge(base) => base.multiply_fixed(x, y, z),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::X86V128Medium { base, proof } | Self::X86V128Large { base, proof } => {
                base.multiply_fixed_x86(*proof, x, y, z)
            }
        }
    }

    pub(crate) fn square_fixed<const N: usize>(&self, x: &[u64; N], z: &mut [u64; N]) {
        self.base().square_fixed(x, z);
    }
}

impl BinPolyMul for BinPolyMultiplier {
    fn n(&self) -> usize {
        self.base().n
    }

    fn size(&self) -> usize {
        self.base().size
    }

    fn multiply(&self, x: &[u64], y: &[u64], z: &mut [u64]) {
        match self {
            Self::ScalarMedium(base) => base.multiply_medium(x, y, z),
            Self::ScalarLarge(base) => base.multiply_large(x, y, z),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::X86V128Medium { base, proof } => base.multiply_x86_medium(*proof, x, y, z),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::X86V128Large { base, proof } => base.multiply_x86_large(*proof, x, y, z),
        }
    }

    fn square(&self, x: &[u64], z: &mut [u64]) {
        self.base().square(x, z);
    }

    fn square_n(&self, x: &[u64], count: usize, z: &mut [u64]) {
        self.base().square_n(x, count, z);
    }
}

fn validate_degree(n: usize, minimum: usize) -> Result<(), BinPolyError> {
    if n < minimum {
        return Err(BinPolyError::DegreeTooSmall { minimum, actual: n });
    }
    if n > MAX_N {
        return Err(BinPolyError::DegreeTooLarge {
            maximum: MAX_N,
            actual: n,
        });
    }
    Ok(())
}

fn expand_square(x: &[u64], zz: &mut [u64]) {
    debug_assert_eq!(zz.len(), x.len() * 2);
    for (i, &word) in x.iter().enumerate() {
        zz[i * 2] = expand32(word as u32);
        zz[i * 2 + 1] = expand32((word >> 32) as u32);
    }
}

#[inline]
fn expand32(value: u32) -> u64 {
    let mut z = u64::from(value);
    z = (z | z << 16) & 0x0000_FFFF_0000_FFFF;
    z = (z | z << 8) & 0x00FF_00FF_00FF_00FF;
    z = (z | z << 4) & 0x0F0F_0F0F_0F0F_0F0F;
    z = (z | z << 2) & 0x3333_3333_3333_3333;
    (z | z << 1) & 0x5555_5555_5555_5555
}

fn debug_assert_reduced(_n: usize, _value: &[u64]) {
    #[cfg(debug_assertions)]
    if _n & 63 != 0 {
        debug_assert_eq!(
            _value[_value.len() - 1] >> (_n & 63),
            0,
            "input is not reduced"
        );
    }
}

struct ClearOnDrop<'a> {
    words: &'a mut [u64],
}

impl<'a> ClearOnDrop<'a> {
    fn new(words: &'a mut [u64]) -> Self {
        Self { words }
    }

    fn as_mut(&mut self) -> &mut [u64] {
        self.words
    }

    fn as_ref(&self) -> &[u64] {
        self.words
    }
}

impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        clear(self.words);
    }
}

struct FixedExtendedScratch<const N: usize>([[u64; N]; 2]);

impl<const N: usize> FixedExtendedScratch<N> {
    fn as_mut(&mut self) -> &mut [u64] {
        self.0.as_flattened_mut()
    }
}

impl<const N: usize> Drop for FixedExtendedScratch<N> {
    fn drop(&mut self) {
        clear(self.0.as_flattened_mut());
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn factories_validate_parameters() {
        assert!(matches!(
            BinPolyMultiplier::binomial(0),
            Err(BinPolyError::DegreeTooSmall { .. })
        ));
        assert!(matches!(
            BinPolyMultiplier::trinomial(2, 1),
            Err(BinPolyError::DegreeTooSmall { .. })
        ));
        assert!(matches!(
            BinPolyMultiplier::trinomial(113, 113),
            Err(BinPolyError::InvalidTrinomialTap { .. })
        ));
        assert!(matches!(
            BinPolyMultiplier::pentanomial(163, 3, 3, 7),
            Err(BinPolyError::InvalidPentanomialTaps { .. })
        ));
    }

    #[test]
    fn square_matches_multiply() {
        for multiplier in [
            BinPolyMultiplier::trinomial(113, 9).unwrap(),
            BinPolyMultiplier::pentanomial(163, 3, 6, 7).unwrap(),
        ] {
            let mut x = vec![0_u64; multiplier.size()];
            x[0] = 0x0123_4567_89AB_CDEF;
            x[1] = 0x0001_2345_6789_ABCD;
            let mut expected = vec![0_u64; multiplier.size()];
            let mut actual = vec![0_u64; multiplier.size()];
            multiplier.multiply(&x, &x, &mut expected);
            multiplier.square(&x, &mut actual);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn repeated_square_matches_individual_squares() {
        let multiplier = BinPolyMultiplier::trinomial(113, 9).unwrap();
        let x = [5_u64, 7];
        let mut expected = [0_u64; 2];
        let mut temporary = [0_u64; 2];
        multiplier.square(&x, &mut expected);
        multiplier.square(&expected, &mut temporary);
        multiplier.square(&temporary, &mut expected);

        let mut actual = [0_u64; 2];
        multiplier.square_n(&x, 3, &mut actual);
        assert_eq!(actual, expected);
    }

    #[derive(Clone, Copy)]
    enum ReferenceModulus {
        Binomial(usize),
        Trinomial(usize, usize),
        Pentanomial(usize, usize, usize, usize),
    }

    impl ReferenceModulus {
        fn n(self) -> usize {
            match self {
                Self::Binomial(n) | Self::Trinomial(n, _) | Self::Pentanomial(n, ..) => n,
            }
        }

        fn multiplier(self) -> BinPolyMultiplier {
            match self {
                Self::Binomial(n) => BinPolyMultiplier::binomial(n).unwrap(),
                Self::Trinomial(n, k) => BinPolyMultiplier::trinomial(n, k).unwrap(),
                Self::Pentanomial(n, k1, k2, k3) => {
                    BinPolyMultiplier::pentanomial(n, k1, k2, k3).unwrap()
                }
            }
        }
    }

    fn reference_multiply(modulus: ReferenceModulus, x: &[u64], y: &[u64]) -> Vec<u64> {
        let n = modulus.n();
        let words = size(n);
        let mut zz = vec![0_u64; words * 2];

        // Independent shift-and-XOR carryless product.
        for bit in 0..n {
            if x[bit >> 6] & (1_u64 << (bit & 63)) == 0 {
                continue;
            }
            let word_offset = bit >> 6;
            let bit_offset = bit & 63;
            for (j, &word) in y.iter().enumerate() {
                zz[word_offset + j] ^= word << bit_offset;
                if bit_offset != 0 {
                    zz[word_offset + j + 1] ^= word >> (64 - bit_offset);
                }
            }
        }

        for p in (n..=2 * n - 2).rev() {
            if zz[p >> 6] & (1_u64 << (p & 63)) == 0 {
                continue;
            }
            let q = p - n;
            let mut toggle = |bit: usize| zz[bit >> 6] ^= 1_u64 << (bit & 63);
            match modulus {
                ReferenceModulus::Binomial(_) => toggle(q),
                ReferenceModulus::Trinomial(_, k) => {
                    toggle(q);
                    toggle(q + k);
                }
                ReferenceModulus::Pentanomial(_, k1, k2, k3) => {
                    toggle(q);
                    toggle(q + k1);
                    toggle(q + k2);
                    toggle(q + k3);
                }
            }
        }

        zz.truncate(words);
        if n & 63 != 0 {
            zz[words - 1] &= (1_u64 << (n & 63)) - 1;
        }
        zz
    }

    fn next(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn real_curve_parameters_match_reference() {
        let moduli = [
            ReferenceModulus::Trinomial(113, 9),
            ReferenceModulus::Trinomial(193, 15),
            ReferenceModulus::Trinomial(233, 74),
            ReferenceModulus::Trinomial(239, 158),
            ReferenceModulus::Trinomial(409, 87),
            ReferenceModulus::Pentanomial(131, 2, 3, 8),
            ReferenceModulus::Pentanomial(163, 3, 6, 7),
            ReferenceModulus::Pentanomial(283, 5, 7, 12),
            ReferenceModulus::Pentanomial(571, 2, 5, 10),
            ReferenceModulus::Binomial(64),
            ReferenceModulus::Binomial(127),
        ];
        let mut seed = 0xB1A2_0F17_5EED_5678_u64;

        for modulus in moduli {
            let multiplier = modulus.multiplier();
            for _ in 0..4 {
                let mut x: Vec<_> = (0..multiplier.size()).map(|_| next(&mut seed)).collect();
                let mut y: Vec<_> = (0..multiplier.size()).map(|_| next(&mut seed)).collect();
                if multiplier.n() & 63 != 0 {
                    let mask = (1_u64 << (multiplier.n() & 63)) - 1;
                    let last = multiplier.size() - 1;
                    x[last] &= mask;
                    y[last] &= mask;
                }
                let expected = reference_multiply(modulus, &x, &y);
                let mut actual = vec![0_u64; multiplier.size()];
                multiplier.multiply(&x, &y, &mut actual);
                assert_eq!(actual, expected, "n={}", multiplier.n());
            }
        }
    }

    #[test]
    fn heap_scratch_path_is_functional() {
        let multiplier = BinPolyMultiplier::trinomial(4097, 9).unwrap();
        assert!(multiplier.size() * 2 > STACK_ALLOC_CUTOFF);
        let mut x = vec![0_u64; multiplier.size()];
        let mut y = vec![0_u64; multiplier.size()];
        x[0] = 3;
        y[0] = 7;
        let mut z = vec![0_u64; multiplier.size()];
        multiplier.multiply(&x, &y, &mut z);
        assert_eq!(z[0], 9);
        assert!(z[1..].iter().all(|&word| word == 0));
    }
}
