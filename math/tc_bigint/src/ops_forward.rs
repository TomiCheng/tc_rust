//! Forwarding implementations for the borrowed operand combinations.
//!
//! Rust requires a separate `impl` for each owned/borrowed pairing, and only
//! the fully owned one carries logic. These macros generate the rest from it,
//! so a new operator needs one body instead of six.

/// Generates the borrowed and assigning forms of a binary operator for a
/// const-generic type whose owned-owned implementation already exists.
macro_rules! forward_binop_fixed {
    ($trait:ident, $method:ident, $assign_trait:ident, $assign_method:ident, $ty:ident) => {
        impl<const N: usize> $trait<&Self> for $ty<N> {
            type Output = Self;
            fn $method(self, rhs: &Self) -> Self {
                $trait::$method(self, *rhs)
            }
        }

        impl<const N: usize> $trait<$ty<N>> for &$ty<N> {
            type Output = $ty<N>;
            fn $method(self, rhs: $ty<N>) -> Self::Output {
                $trait::$method(*self, rhs)
            }
        }

        impl<const N: usize> $trait<&$ty<N>> for &$ty<N> {
            type Output = $ty<N>;
            fn $method(self, rhs: &$ty<N>) -> Self::Output {
                $trait::$method(*self, *rhs)
            }
        }

        impl<const N: usize> $assign_trait<&Self> for $ty<N> {
            fn $assign_method(&mut self, rhs: &Self) {
                *self = $trait::$method(*self, *rhs);
            }
        }

        impl<const N: usize> $assign_trait for $ty<N> {
            fn $assign_method(&mut self, rhs: Self) {
                *self = $trait::$method(*self, rhs);
            }
        }
    };
}

pub(crate) use forward_binop_fixed;
