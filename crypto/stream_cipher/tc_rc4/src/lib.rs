//! RC4 stream cipher.
//!
//! RC4 encryption and decryption are the same XOR operation. The direction
//! supplied during initialization is therefore accepted but does not change
//! the generated keystream.
//!
//! RC4 is cryptographically broken and is provided only for compatibility and
//! study. It must not be used in new protocols.
//!
//! ```
//! use tc_cipher::{CipherDirection, StreamCipher, StreamCipherInit};
//! use tc_params::KeyRef;
//! use tc_rc4::Rc4Engine;
//!
//! let mut cipher = Rc4Engine::new();
//! cipher.init(CipherDirection::Encrypt, &KeyRef::new(b"Key"))?;
//!
//! let mut output = [0u8; 9];
//! cipher.process_bytes(b"Plaintext", &mut output)?;
//! assert_eq!(output, [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod engine;

pub use engine::Rc4Engine;

/// Maximum RC4 key length in bytes.
pub const MAX_KEY_BYTES: usize = 256;
