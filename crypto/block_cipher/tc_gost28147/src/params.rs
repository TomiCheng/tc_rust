//! A convenience [`KeyWithSBoxParams`] implementation.

use tc_params::{KeyParams, KeyWithSBoxParams};

use crate::s_box;

/// A borrowed key paired with the S-box to run it under.
///
/// [`KeyWithSBoxParams`] leaves the choice of table entirely to the caller, so
/// this type is where the Bouncy Castle convention lives: [`new`](Self::new)
/// selects [`s_box::DEFAULT`]. Callers with their own parameter type can
/// implement the trait directly instead.
///
/// ```
/// use tc_gost28147::{KeyWithSBox, s_box};
/// use tc_params::{KeyParams, KeyWithSBoxParams};
///
/// let key = [0u8; 32];
/// assert_eq!(KeyWithSBox::new(&key).s_box(), s_box::DEFAULT);
///
/// let params = KeyWithSBox::with_s_box(&key, &s_box::E_A);
/// assert_eq!(params.key(), &key);
/// assert_eq!(params.s_box(), s_box::E_A);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct KeyWithSBox<'a> {
    key: &'a [u8],
    s_box: &'a [u8],
}

impl<'a> KeyWithSBox<'a> {
    /// Pairs `key` with [`s_box::DEFAULT`].
    pub const fn new(key: &'a [u8]) -> Self {
        Self::with_s_box(key, &s_box::DEFAULT)
    }

    /// Pairs `key` with `s_box`, which the engine will check.
    pub const fn with_s_box(key: &'a [u8], s_box: &'a [u8]) -> Self {
        Self { key, s_box }
    }
}

impl KeyParams for KeyWithSBox<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl KeyWithSBoxParams for KeyWithSBox<'_> {
    fn s_box(&self) -> &[u8] {
        self.s_box
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::boxed::Box;

    use super::*;

    #[test]
    fn a_bare_key_runs_with_the_default_table() {
        let key = [0x5a_u8; 32];
        let params = KeyWithSBox::new(&key);
        assert_eq!(params.key(), &key);
        assert_eq!(params.s_box(), s_box::DEFAULT);
    }

    #[test]
    fn any_table_can_be_paired_with_a_key() {
        let key = [0x5a_u8; 32];
        for table in [s_box::E_A, s_box::E_B, s_box::D_A] {
            assert_eq!(KeyWithSBox::with_s_box(&key, &table).s_box(), table);
        }
    }

    #[test]
    fn the_table_is_handed_over_unchecked() {
        // params 只搬位元組;長度與內容由引擎負責。
        let key = [0_u8; 32];
        assert_eq!(KeyWithSBox::with_s_box(&key, &[]).s_box(), &[] as &[u8]);
    }

    #[test]
    fn is_usable_through_a_trait_object() {
        let key = [0x11_u8; 32];
        let params: &dyn KeyWithSBoxParams = &KeyWithSBox::new(&key);
        assert_eq!(params.s_box().len(), s_box::BYTES);

        let boxed: Box<dyn KeyWithSBoxParams> = Box::new(KeyWithSBox::new(&key));
        assert_eq!(boxed.key(), &key);
    }
}
