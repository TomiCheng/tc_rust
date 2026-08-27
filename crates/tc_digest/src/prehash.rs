//! Fixed-length prehash pass-through wrapper, ported from Bouncy Castle's
//! `Prehash`.
//!
//! `Prehash` does not calculate a hash. It accepts exactly one already-computed
//! digest value and returns those bytes unchanged through the [`TryDigest`]
//! interface. This is useful when an API expects a digest object but its caller
//! has already hashed the message.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use tc_crypto_core::TryDigest;

/// Errors produced by [`Prehash`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrehashError {
    /// An update would exceed the configured digest size.
    InputTooLong {
        /// Maximum accepted number of bytes.
        limit: usize,
        /// Total number of bytes that the update attempted to reach.
        attempted: usize,
    },
    /// Finalization was requested before exactly one digest value was supplied.
    IncorrectLength {
        /// Required prehash length.
        expected: usize,
        /// Number of bytes supplied before finalization.
        actual: usize,
    },
}

impl fmt::Display for PrehashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrehashError::InputTooLong { limit, attempted } => write!(
                f,
                "prehash input too long: limit is {limit} bytes, attempted {attempted} bytes"
            ),
            PrehashError::IncorrectLength { expected, actual } => write!(
                f,
                "incorrect prehash length: expected {expected} bytes, got {actual} bytes"
            ),
        }
    }
}

impl core::error::Error for PrehashError {}

/// A fixed-length pass-through for an already-computed digest value.
///
/// Unlike [`crate::NullDigest`], this wrapper accepts exactly `digest_size`
/// bytes. It deliberately implements only the fallible [`TryDigest`] API so
/// incorrect prehash lengths are returned as [`PrehashError`] rather than
/// panicking.
#[derive(Clone, Debug)]
pub struct Prehash {
    algorithm_name: String,
    buffer: Vec<u8>,
    position: usize,
}

impl Prehash {
    /// Creates a prehash wrapper with an explicit algorithm name and size.
    pub fn for_parameters(algorithm_name: impl Into<String>, digest_size: usize) -> Self {
        Self {
            algorithm_name: algorithm_name.into(),
            buffer: vec![0; digest_size],
            position: 0,
        }
    }

    /// Creates a prehash wrapper matching another digest's name and output size.
    pub fn for_digest<D: TryDigest + ?Sized>(digest: &D) -> Self {
        Self::for_parameters(digest.algorithm_name().to_string(), digest.digest_size())
    }

    /// Returns the number of prehash bytes currently buffered.
    pub fn len(&self) -> usize {
        self.position
    }

    /// Returns whether no prehash bytes are currently buffered.
    pub fn is_empty(&self) -> bool {
        self.position == 0
    }
}

impl TryDigest for Prehash {
    type Error = PrehashError;

    fn algorithm_name(&self) -> &str {
        &self.algorithm_name
    }

    fn digest_size(&self) -> usize {
        self.buffer.len()
    }

    /// Returns the configured digest size as the compatibility byte length.
    ///
    /// Bouncy Castle's `Prehash.GetByteLength()` is unsupported. This Rust API
    /// requires a `usize`, so the fixed prehash size is the least surprising
    /// useful value.
    fn byte_length(&self) -> usize {
        self.buffer.len()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let attempted = self.position.saturating_add(input.len());
        if input.len() > self.buffer.len() - self.position {
            return Err(PrehashError::InputTooLong {
                limit: self.buffer.len(),
                attempted,
            });
        }

        let end = self.position + input.len();
        self.buffer[self.position..end].copy_from_slice(input);
        self.position = end;
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let expected = self.buffer.len();
        let actual = self.position;
        if actual != expected {
            self.position = 0;
            return Err(PrehashError::IncorrectLength { expected, actual });
        }

        output[..expected].copy_from_slice(&self.buffer);
        self.position = 0;
        Ok(expected)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.position = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sha256Digest;

    #[test]
    fn passes_exact_prehashed_value_through() {
        let expected: Vec<u8> = (0..32).collect();
        let mut prehash = Prehash::for_parameters("SHA-256", 32);

        prehash.try_update(&expected[..7]).unwrap();
        prehash.try_update(&expected[7..]).unwrap();
        assert_eq!(prehash.algorithm_name(), "SHA-256");
        assert_eq!(prehash.digest_size(), 32);
        assert_eq!(prehash.byte_length(), 32);
        assert_eq!(prehash.len(), 32);

        let mut output = [0u8; 32];
        assert_eq!(prehash.try_do_final(&mut output).unwrap(), 32);
        assert_eq!(output.as_slice(), expected);
        assert!(prehash.is_empty());
    }

    #[test]
    fn for_digest_copies_name_and_size() {
        let source = Sha256Digest::new();
        let prehash = Prehash::for_digest(&source);
        assert_eq!(prehash.algorithm_name(), "SHA-256");
        assert_eq!(prehash.digest_size(), 32);
        assert_eq!(prehash.byte_length(), 32);
    }

    #[test]
    fn overflow_is_rejected_without_changing_buffered_input() {
        let mut prehash = Prehash::for_parameters("TEST-32", 4);
        prehash.try_update(&[1, 2]).unwrap();

        assert_eq!(
            prehash.try_update(&[3, 4, 5]),
            Err(PrehashError::InputTooLong {
                limit: 4,
                attempted: 5,
            })
        );
        assert_eq!(prehash.len(), 2);

        prehash.try_update(&[3, 4]).unwrap();
        let mut output = [0u8; 4];
        prehash.try_do_final(&mut output).unwrap();
        assert_eq!(output, [1, 2, 3, 4]);
    }

    #[test]
    fn incorrect_final_length_returns_error_and_resets() {
        let mut prehash = Prehash::for_parameters("TEST-32", 4);
        prehash.try_update(&[1, 2]).unwrap();

        let mut output = [0u8; 4];
        assert_eq!(
            prehash.try_do_final(&mut output),
            Err(PrehashError::IncorrectLength {
                expected: 4,
                actual: 2,
            })
        );
        assert!(prehash.is_empty());

        prehash.try_update(&[5, 6, 7, 8]).unwrap();
        prehash.try_do_final(&mut output).unwrap();
        assert_eq!(output, [5, 6, 7, 8]);
    }

    #[test]
    fn reset_and_clone_keep_configuration() {
        let mut prehash = Prehash::for_parameters("TEST-16", 2);
        prehash.try_update(&[9]).unwrap();
        let cloned = prehash.clone();
        assert_eq!(cloned.len(), 1);
        assert_eq!(cloned.algorithm_name(), "TEST-16");

        prehash.try_reset().unwrap();
        assert!(prehash.is_empty());
        assert_eq!(prehash.digest_size(), 2);
    }

    #[test]
    fn zero_length_prehash_is_supported() {
        let mut prehash = Prehash::for_parameters("EMPTY", 0);
        let mut output = [];
        assert_eq!(prehash.try_do_final(&mut output).unwrap(), 0);
        assert_eq!(
            prehash.try_update_byte(1),
            Err(PrehashError::InputTooLong {
                limit: 0,
                attempted: 1,
            })
        );
    }
}
