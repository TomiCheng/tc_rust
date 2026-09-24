//! Convenience implementation of [`Rc5Params`].

use core::fmt;

use tc_block_cipher::KeyParams;

/// Supplies an RC5 key and public round count.
///
/// Timing is implementation-defined; implementations should avoid secret-dependent
/// work when returning the key and parameters.
pub trait Rc5Params: KeyParams {
    /// Returns the round count. Timing is implementation-defined.
    fn rounds(&self) -> usize;
}

/// Borrowed RC5 key and round-count parameters.
///
/// This type does not validate either value; an RC5 engine validates them when
/// initialized. Callers with their own parameter type can implement
/// [`Rc5Params`] directly.
/// Constant time: construction and access do not inspect key contents.
#[derive(Clone, Copy)]
pub struct Params<'a> {
    key: &'a [u8],
    rounds: usize,
}

impl<'a> Params<'a> {
    /// Creates RC5 parameters with an explicit round count. Constant time.
    pub const fn new(key: &'a [u8], rounds: usize) -> Self {
        Self { key, rounds }
    }

    /// Creates RC5 parameters with the standard twelve rounds. Constant time.
    pub const fn with_default_rounds(key: &'a [u8]) -> Self {
        Self::new(key, crate::DEFAULT_ROUNDS)
    }
}

impl KeyParams for Params<'_> {
    /// Borrows the key without inspecting it. Constant time.
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Rc5Params for Params<'_> {
    /// Returns the stored public round count. Constant time.
    fn rounds(&self) -> usize {
        self.rounds
    }
}

impl fmt::Debug for Params<'_> {
    /// Writes public parameters without revealing key bytes.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Params")
            .field("key_len", &self.key.len())
            .field("rounds", &self.rounds)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    #[test]
    fn exposes_explicit_and_default_round_counts() {
        assert_eq!(Params::new(&[0u8; 8], 16).rounds(), 16);
        assert_eq!(
            Params::with_default_rounds(&[0u8; 8]).rounds(),
            crate::DEFAULT_ROUNDS
        );
    }

    #[test]
    fn debug_redacts_the_key() {
        let params = Params::new(&[0xff; 8], 16);
        assert_eq!(format!("{params:?}"), "Params { key_len: 8, rounds: 16 }");
    }
}
