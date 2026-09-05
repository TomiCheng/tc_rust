use core::fmt;

/// Error returned when constructing or combining binary polynomials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinPolyError {
    /// The polynomial degree is below the minimum for this modulus shape.
    DegreeTooSmall { minimum: usize, actual: usize },
    /// The polynomial degree exceeds [`crate::MAX_N`].
    DegreeTooLarge { maximum: usize, actual: usize },
    /// A trinomial tap did not satisfy `0 < k < n`.
    InvalidTrinomialTap { n: usize, k: usize },
    /// Pentanomial taps did not satisfy `0 < k1 < k2 < k3 < n`.
    InvalidPentanomialTaps {
        n: usize,
        k1: usize,
        k2: usize,
        k3: usize,
    },
    /// A limb slice had the wrong length.
    InvalidLength { expected: usize, actual: usize },
    /// Bits at positions greater than or equal to the configured degree were set.
    UnreducedValue,
    /// Both values must use the same reduction polynomial.
    MismatchedModulus,
    /// Inversion is unavailable for the reducible binomial modulus `x^n + 1`.
    BinomialInversion,
    /// At least one squaring was required.
    InvalidSquareCount,
}

impl fmt::Display for BinPolyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::DegreeTooSmall { minimum, actual } => {
                write!(f, "degree must be at least {minimum}, got {actual}")
            }
            Self::DegreeTooLarge { maximum, actual } => {
                write!(f, "degree must be at most {maximum}, got {actual}")
            }
            Self::InvalidTrinomialTap { n, k } => {
                write!(f, "trinomial tap must satisfy 0 < k < n, got n={n}, k={k}")
            }
            Self::InvalidPentanomialTaps { n, k1, k2, k3 } => write!(
                f,
                "pentanomial taps must satisfy 0 < k1 < k2 < k3 < n, got n={n}, taps=({k1}, {k2}, {k3})"
            ),
            Self::InvalidLength { expected, actual } => {
                write!(f, "expected {expected} limbs, got {actual}")
            }
            Self::UnreducedValue => {
                f.write_str("value has coefficients at or above the modulus degree")
            }
            Self::MismatchedModulus => f.write_str("binary polynomials use different moduli"),
            Self::BinomialInversion => {
                f.write_str("x^n + 1 is reducible and cannot be used for field inversion")
            }
            Self::InvalidSquareCount => f.write_str("square count must be positive"),
        }
    }
}

impl core::error::Error for BinPolyError {}
