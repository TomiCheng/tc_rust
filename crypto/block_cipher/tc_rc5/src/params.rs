//! Convenience implementation of [`Rc5Params`].

use core::fmt;

use tc_params::{KeyParams, Rc5Params};

/// Borrowed RC5 key and round-count parameters.
///
/// This type does not validate either value; an RC5 engine validates them when
/// initialized. Callers with their own parameter type can implement
/// [`Rc5Params`] directly.
#[derive(Clone, Copy)]
pub struct Params<'a> {
    key: &'a [u8],
    rounds: usize,
}

impl<'a> Params<'a> {
    /// Creates RC5 parameters with an explicit round count.
    pub const fn new(key: &'a [u8], rounds: usize) -> Self {
        Self { key, rounds }
    }

    /// Creates RC5 parameters with the standard twelve rounds.
    pub const fn with_default_rounds(key: &'a [u8]) -> Self {
        Self::new(key, crate::DEFAULT_ROUNDS)
    }
}

impl KeyParams for Params<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Rc5Params for Params<'_> {
    fn rounds(&self) -> usize {
        self.rounds
    }
}

impl fmt::Debug for Params<'_> {
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
