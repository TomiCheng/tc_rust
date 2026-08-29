//! IDEA (International Data Encryption Algorithm) 64-bit block cipher, ported
//! from Bouncy Castle's `IdeaEngine`.
//!
//! IDEA uses a 128-bit key and a 64-bit block, running eight identical rounds
//! followed by an output transform. Encryption and decryption share the same
//! round function; only the working key differs (the decryption key is the
//! multiplicative/additive inverse of the expanded encryption key), so the
//! direction is fixed at [`init`](tc_cipher_core::BlockCipherInit::init) time.
//!
//! Bouncy Castle accepts any key length, left-padding a short key with zeros and
//! silently using only the first sixteen bytes of a longer one. This port instead
//! requires exactly sixteen bytes, matching the algorithm's 128-bit key.
//!
//! ```
//! use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_block_cipher::{IdeaEngine, IdeaParams};
//!
//! let key = [
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//!     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
//! ];
//! let params = IdeaParams::new(&key)?;
//! let mut cipher = IdeaEngine::new();
//! cipher.init(CipherDirection::Encrypt, &params)?;
//!
//! let plaintext: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
//! let mut ciphertext = [0u8; 8];
//! cipher.process_block(&plaintext, &mut ciphertext)?;
//!
//! cipher.init(CipherDirection::Decrypt, &params)?;
//! let mut recovered = [0u8; 8];
//! cipher.process_block(&ciphertext, &mut recovered)?;
//! assert_eq!(recovered, plaintext);
//! # Ok::<(), tc_block_cipher::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod engine;
mod params;

pub use engine::IdeaEngine;
pub use params::IdeaParams;

/// IDEA key length in bytes (128 bits).
pub const IDEA_KEY_BYTES: usize = 16;
/// IDEA block length in bytes (64 bits).
pub const IDEA_BLOCK_BYTES: usize = 8;
