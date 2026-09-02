//! SCHWAEMM authenticated encryption based on the SPARKLE permutation.
//!
//! # Example
//!
//! ```
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//! use tc_sparkle_aead::{Engine, Params, Variant};
//!
//! let key = core::array::from_fn::<_, 16, _>(|i| i as u8);
//! let nonce = core::array::from_fn::<_, 16, _>(|i| i as u8);
//! let aad = core::array::from_fn::<_, 16, _>(|i| i as u8);
//! let plaintext = core::array::from_fn::<_, 16, _>(|i| i as u8);
//! let params = Params::new(&key, &nonce, &[]);
//!
//! let mut cipher = Engine::new(Variant::Schwaemm128_128);
//! cipher.init(CipherDirection::Encrypt, &params)?;
//! cipher.process_aad_bytes(&aad)?;
//!
//! let mut output = [0_u8; 32];
//! let mut written = cipher.process_bytes(&plaintext, &mut output)?;
//! written += cipher.do_final(&mut output[written..])?;
//!
//! assert_eq!(written, output.len());
//! assert_eq!(
//!     output,
//!     [
//!         0xCA, 0xD1, 0x20, 0x8F, 0x3D, 0x3F, 0xEC, 0x73,
//!         0xD1, 0xE8, 0x82, 0x5F, 0xBD, 0xD4, 0x6C, 0x88,
//!         0x0B, 0x9A, 0xC7, 0xE5, 0x25, 0x0D, 0x69, 0x20,
//!         0x03, 0x96, 0x84, 0x72, 0x19, 0xFE, 0xBA, 0x1F,
//!     ],
//! );
//!
//! let mut decipher = Engine::new(Variant::Schwaemm128_128);
//! decipher.init(CipherDirection::Decrypt, &params)?;
//! decipher.process_aad_bytes(&aad)?;
//!
//! let mut recovered = [0_u8; 16];
//! let mut recovered_len = decipher.process_bytes(&output, &mut recovered)?;
//! recovered_len += decipher.do_final(&mut recovered[recovered_len..])?;
//!
//! assert_eq!(recovered_len, plaintext.len());
//! assert_eq!(recovered, plaintext);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

mod engine;
mod params;

pub use engine::Engine;
pub use params::Params;

/// SCHWAEMM parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// SCHWAEMM128-128: 128-bit key, nonce, tag, and rate.
    Schwaemm128_128,
    /// SCHWAEMM256-128: 128-bit key and tag with a 256-bit nonce and rate.
    Schwaemm256_128,
    /// SCHWAEMM192-192: 192-bit key, nonce, tag, and rate.
    Schwaemm192_192,
    /// SCHWAEMM256-256: 256-bit key, nonce, tag, and rate.
    Schwaemm256_256,
}

impl Variant {
    /// Returns the required key length in bytes.
    pub const fn key_bytes(self) -> usize {
        match self {
            Self::Schwaemm128_128 | Self::Schwaemm256_128 => BYTES_128,
            Self::Schwaemm192_192 => BYTES_192,
            Self::Schwaemm256_256 => BYTES_256,
        }
    }

    /// Returns the required nonce length in bytes.
    pub const fn nonce_bytes(self) -> usize {
        match self {
            Self::Schwaemm128_128 => BYTES_128,
            Self::Schwaemm192_192 => BYTES_192,
            Self::Schwaemm256_128 | Self::Schwaemm256_256 => BYTES_256,
        }
    }

    /// Returns the authentication-tag length in bytes.
    pub const fn tag_bytes(self) -> usize {
        self.key_bytes()
    }

    const fn state_words(self) -> usize {
        match self {
            Self::Schwaemm128_128 => 8,
            Self::Schwaemm256_128 | Self::Schwaemm192_192 => 12,
            Self::Schwaemm256_256 => 16,
        }
    }

    const fn slim_steps(self) -> usize {
        match self {
            Self::Schwaemm256_256 => 8,
            _ => 7,
        }
    }

    const fn big_steps(self) -> usize {
        match self {
            Self::Schwaemm128_128 => 10,
            Self::Schwaemm256_128 | Self::Schwaemm192_192 => 11,
            Self::Schwaemm256_256 => 12,
        }
    }

    const fn algorithm_name(self) -> &'static str {
        match self {
            Self::Schwaemm128_128 => "SCHWAEMM128-128",
            Self::Schwaemm256_128 => "SCHWAEMM256-128",
            Self::Schwaemm192_192 => "SCHWAEMM192-192",
            Self::Schwaemm256_256 => "SCHWAEMM256-256",
        }
    }
}

/// Number of bytes in a 128-bit SCHWAEMM parameter.
pub const BYTES_128: usize = 16;
/// Number of bytes in a 192-bit SCHWAEMM parameter.
pub const BYTES_192: usize = 24;
/// Number of bytes in a 256-bit SCHWAEMM parameter.
pub const BYTES_256: usize = 32;
