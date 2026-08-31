//! Legacy Ascon v1.2 AEAD variants.
//!
//! For the finalized NIST SP 800-232 algorithm, use
//! [`crate::ascon_aead128`] instead.

mod engine;
mod params;
mod traits;

pub use engine::Engine;
pub use params::BorrowedParams;
#[cfg(feature = "alloc")]
pub use params::OwnedParams;
pub use traits::Params;

/// Legacy Ascon-AEAD variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Ascon-128 with a 128-bit key and 64-bit rate.
    Ascon128,
    /// Ascon-128a with a 128-bit key and 128-bit rate.
    Ascon128a,
    /// Ascon-80pq with a 160-bit key and 64-bit rate.
    Ascon80pq,
}

impl Variant {
    /// Returns the required key length in bytes.
    pub const fn key_bytes(self) -> usize {
        match self {
            Self::Ascon128 | Self::Ascon128a => KEY_BYTES_128,
            Self::Ascon80pq => KEY_BYTES_80PQ,
        }
    }

    const fn rate(self) -> usize {
        match self {
            Self::Ascon128 | Self::Ascon80pq => 8,
            Self::Ascon128a => 16,
        }
    }

    const fn rounds(self) -> usize {
        match self {
            Self::Ascon128 | Self::Ascon80pq => 6,
            Self::Ascon128a => 8,
        }
    }

    const fn initialisation_value(self) -> u64 {
        match self {
            Self::Ascon128 => 0x8040_0c06_0000_0000,
            Self::Ascon128a => 0x8080_0c08_0000_0000,
            Self::Ascon80pq => 0xa040_0c06_0000_0000,
        }
    }

    const fn algorithm_name(self) -> &'static str {
        match self {
            Self::Ascon128 => "Ascon-128 AEAD",
            Self::Ascon128a => "Ascon-128a AEAD",
            Self::Ascon80pq => "Ascon-80pq AEAD",
        }
    }
}

/// Key length for Ascon-128 and Ascon-128a in bytes.
pub const KEY_BYTES_128: usize = 16;

/// Key length for Ascon-80pq in bytes.
pub const KEY_BYTES_80PQ: usize = 20;

/// Nonce length for every legacy Ascon AEAD variant in bytes.
pub const NONCE_BYTES: usize = 16;

/// Authentication-tag length for every legacy Ascon AEAD variant in bytes.
pub const TAG_BYTES: usize = 16;
