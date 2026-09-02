//! Legacy Ascon v1.2 authenticated-encryption algorithms.
//!
//! These variants are retained only for compatibility with protocols that
//! explicitly require Ascon v1.2. New designs should use
//! [`crate::aead128::Engine`], which implements NIST SP 800-232.
//!
//! ```
//! use tc_ascon_aead::legacy::{Engine, KEY_BYTES_128, NONCE_BYTES, Params, TAG_BYTES, Variant};
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//!
//! let key = [0_u8; KEY_BYTES_128];
//! let nonce = [1_u8; NONCE_BYTES];
//! let params = Params::new(&key, &nonce, b"header");
//! let mut cipher = Engine::new(Variant::Ascon128);
//! cipher.init(CipherDirection::Encrypt, &params).unwrap();
//!
//! let mut output = [0_u8; 7 + TAG_BYTES];
//! let mut written = cipher.process_bytes(b"message", &mut output).unwrap();
//! written += cipher.do_final(&mut output[written..]).unwrap();
//! assert_eq!(written, output.len());
//! ```

mod engine;

pub use crate::Params;
pub use engine::Engine;

/// Legacy Ascon v1.2 AEAD variant.
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

/// Nonce length for every legacy Ascon v1.2 AEAD variant in bytes.
pub const NONCE_BYTES: usize = 16;

/// Authentication-tag length for every legacy Ascon v1.2 variant in bytes.
pub const TAG_BYTES: usize = 16;
