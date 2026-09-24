//! A convenience key-and-S-box parameter implementation.

use core::fmt;

use tc_block_cipher::KeyParams;

use crate::s_box;

/// Supplies an S-box to a GOST 28147 engine.
///
/// Timing is implementation-defined; implementations should avoid
/// secret-dependent work when returning the borrowed table.
pub trait SBoxParams {
    /// Returns the S-box bytes. Timing is implementation-defined.
    fn s_box(&self) -> &[u8];
}

/// A borrowed key paired with the S-box to run it under.
///
/// [`SBoxParams`] leaves the choice of table entirely to the caller, so
/// this type is where the Bouncy Castle convention lives: [`new`](Self::new)
/// selects [`s_box::DEFAULT`]. Callers with their own parameter type can
/// implement the trait directly instead. No validation occurs here.
/// Constant time: construction and access do not inspect key or table contents.
///
/// ```
/// use tc_gost28147_v2::{KeyWithSBox, SBoxParams, s_box};
/// use tc_block_cipher::KeyParams;
///
/// let key = [0u8; 32];
/// assert_eq!(KeyWithSBox::new(&key).s_box(), s_box::DEFAULT);
///
/// let params = KeyWithSBox::with_s_box(&key, &s_box::E_A);
/// assert_eq!(params.key(), &key);
/// assert_eq!(params.s_box(), s_box::E_A);
/// ```
#[derive(Clone, Copy)]
pub struct KeyWithSBox<'a> {
    key: &'a [u8],
    s_box: &'a [u8],
}

impl<'a> KeyWithSBox<'a> {
    /// Pairs `key` with [`s_box::DEFAULT`]. Constant time.
    pub const fn new(key: &'a [u8]) -> Self {
        Self::with_s_box(key, &s_box::DEFAULT)
    }

    /// Pairs `key` with `s_box`, which the engine will check. Constant time.
    pub const fn with_s_box(key: &'a [u8], s_box: &'a [u8]) -> Self {
        Self { key, s_box }
    }
}

impl KeyParams for KeyWithSBox<'_> {
    /// Borrows the key without inspecting it. Constant time.
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl SBoxParams for KeyWithSBox<'_> {
    /// Borrows the table without inspecting it. Constant time.
    fn s_box(&self) -> &[u8] {
        self.s_box
    }
}

impl fmt::Debug for KeyWithSBox<'_> {
    /// Writes public lengths without revealing key or S-box bytes.
    /// Constant time with respect to secret contents; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWithSBox")
            .field("key_len", &self.key.len())
            .field("s_box_len", &self.s_box.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    #[test]
    fn debug_redacts_both_key_and_s_box_material() {
        let params = KeyWithSBox::with_s_box(&[0xa5; 32], &[0x5a; 128]);
        assert_eq!(
            format!("{params:?}"),
            "KeyWithSBox { key_len: 32, s_box_len: 128 }"
        );
    }

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
        // Parameters only carry bytes; validation belongs to the engine.
        let key = [0_u8; 32];
        assert_eq!(KeyWithSBox::with_s_box(&key, &[]).s_box(), &[] as &[u8]);
    }

    #[test]
    fn values_are_usable_through_the_individual_traits() {
        let key = [0x11_u8; 32];
        let params = KeyWithSBox::new(&key);

        assert_eq!((&params as &dyn SBoxParams).s_box().len(), s_box::BYTES);
        assert_eq!((&params as &dyn KeyParams).key(), &key);
    }
}
