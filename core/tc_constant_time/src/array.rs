//! Conditional selection and in-place updates for fixed-size arrays.

use crate::{Choice, ConditionallySelectable};

impl<T: ConditionallySelectable, const N: usize> ConditionallySelectable for [T; N] {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        core::array::from_fn(|i| T::conditional_select(&a[i], &b[i], choice))
    }

    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        for (value, source) in self.iter_mut().zip(other) {
            value.conditional_assign(source, choice);
        }
    }

    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        for (left, right) in a.iter_mut().zip(b) {
            T::conditional_swap(left, right, choice);
        }
    }
}
