//! Error types.

// core

mod conversion;
pub use conversion::{ConversionError, ParseBigIntError};

// rand core

#[cfg(feature = "rand_core")]
mod random_bits;
#[cfg(feature = "rand_core")]
pub use random_bits::RandomBitsError;
