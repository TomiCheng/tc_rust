#![no_std]
//! Fixed-width primitives with data-independent control flow and memory access.
//! These contracts concern secret values, not public sizes or domain parameters.
//! Target code generation and hardware still need review for deployment.

/// A bit used for masked selection. Conversion to `bool` deliberately reveals it.
#[derive(Clone, Copy)]
pub struct Choice(u8);
impl Choice {
    /// Keeps the least significant bit, hiding its range from optimization.
    #[inline(always)]
    pub fn from_lsb(value: u8) -> Self {
        Self(core::hint::black_box(value & 1))
    }
    /// Reveals the bit as 0 or 1.
    #[inline(always)]
    pub fn unwrap_u8(self) -> u8 {
        self.0
    }
}
impl core::ops::Not for Choice {
    type Output = Self;
    fn not(self) -> Self {
        Self::from_lsb(self.0 ^ 1)
    }
}
impl core::ops::BitAnd for Choice {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self::from_lsb(self.0 & rhs.0)
    }
}
impl core::ops::BitOr for Choice {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self::from_lsb(self.0 | rhs.0)
    }
}

/// Selects without branches or addresses depending on the choice or values.
pub trait ConditionallySelectable: Sized {
    /// Returns `a` for zero and `b` for one.
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self;
}
/// Equality without early exits on secret values.
pub trait ConstantTimeEq {
    fn ct_eq(&self, rhs: &Self) -> Choice;
}

macro_rules! integers {
    ($($t:ty),*) => {$ (
        impl ConditionallySelectable for $t {
            #[inline(always)]
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                let mask = (0 as $t).wrapping_sub(choice.0 as $t);
                a ^ ((a ^ b) & mask)
            }
        }
        impl ConstantTimeEq for $t {
            #[inline(always)]
            fn ct_eq(&self, rhs: &Self) -> Choice {
                let difference = self ^ rhs;
                Choice::from_lsb((((difference | difference.wrapping_neg()) >> (<$t>::BITS - 1)) ^ 1) as u8)
            }
        }
    )*};
}
integers!(u8, u32, u64, usize);
impl<T: ConditionallySelectable, const N: usize> ConditionallySelectable for [T; N] {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        core::array::from_fn(|i| T::conditional_select(&a[i], &b[i], choice))
    }
}
impl<T: ConstantTimeEq, const N: usize> ConstantTimeEq for [T; N] {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        let mut equal = Choice::from_lsb(1);
        for i in 0..N {
            equal = equal & self[i].ct_eq(&rhs[i]);
        }
        equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn select_and_equal_all_bytes() {
        for a in 0..=255_u8 {
            for b in 0..=255_u8 {
                assert_eq!(u8::conditional_select(&a, &b, Choice::from_lsb(0)), a);
                assert_eq!(u8::conditional_select(&a, &b, Choice::from_lsb(1)), b);
                assert_eq!(a.ct_eq(&b).unwrap_u8(), (a == b) as u8);
            }
        }
    }
}
