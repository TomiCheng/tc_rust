//! Error values returned by prime utilities.

use core::fmt;

/// An invalid input or a failure while testing or generating a prime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimeError {
    /// The candidate is less than two.
    InvalidCandidate,
    /// The Miller-Rabin base is outside the valid range.
    InvalidBase,
    /// The requested Miller-Rabin iteration count is zero.
    InvalidIterations,
    /// The requested Shawe-Taylor prime length is less than two bits.
    InvalidLength,
    /// The Shawe-Taylor input seed is empty.
    EmptySeed,
    /// Shawe-Taylor exceeded the iteration limit specified by the algorithm.
    TooManyIterations,
    /// An intermediate value or result does not fit the selected integer type.
    Overflow,
}

impl fmt::Display for PrimeError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::InvalidCandidate => "candidate must be at least two",
            Self::InvalidBase => "base must be at least two and less than candidate minus one",
            Self::InvalidIterations => "iterations must be greater than zero",
            Self::InvalidLength => "prime length must be at least two bits",
            Self::EmptySeed => "prime seed must not be empty",
            Self::TooManyIterations => "too many Shawe-Taylor iterations",
            Self::Overflow => "value does not fit the target integer type",
        })
    }
}

impl core::error::Error for PrimeError {}

#[cfg(test)]
mod tests {
    use super::PrimeError;
    use std::string::ToString;

    #[test]
    fn display_messages_are_stable() {
        assert_eq!(
            PrimeError::InvalidCandidate.to_string(),
            "candidate must be at least two"
        );
        assert_eq!(
            PrimeError::TooManyIterations.to_string(),
            "too many Shawe-Taylor iterations"
        );
    }
}
