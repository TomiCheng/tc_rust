//! Initialization-vector-bearing parameter abstraction.

/// Parameters that provide an initialization vector.
pub trait Iv {
    /// Returns the initialization-vector bytes.
    fn iv(&self) -> &[u8];
}
