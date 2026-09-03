//! Buffered adapters for block and stream ciphers.
//!
//! [`BufferedBlockCipher`] accepts input in arbitrary-size pieces, emits every
//! complete block, and retains a final partial block until
//! [`BufferedCipher::do_final`](tc_cipher::BufferedCipher::do_final). A mode such as CFB or OFB may process that
//! partial block; ECB and CBC reject it because they require aligned input.
//!
//! The block-cipher adapter sizes its buffer from the wrapped mode at runtime
//! and therefore uses `alloc`. [`BufferedStreamCipher`] does not allocate. The
//! crate remains `no_std`.
//!
//! [`BufferedIesCipher`] collects an entire IES message and emits output only
//! from `do_final`. Its engine reports the configured output size, rather than
//! assuming the 20-byte MAC used by Bouncy Castle's unfinished adapter.
//!
//! ```
//! use tc_aes::AesEngine;
//! use tc_buff::BufferedBlockCipher;
//! use tc_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection};
//! use tc_params::KeyRef;
//!
//! let key = [
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//! ];
//! let plaintext = [
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//!     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
//! ];
//! let expected = [
//!     0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
//!     0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
//! ];
//! let params = KeyRef::new(&key);
//! let mut cipher = BufferedBlockCipher::from_cipher(AesEngine::new());
//! cipher.init(CipherDirection::Encrypt, &params)?;
//!
//! let mut encrypted = [0u8; 16];
//! assert_eq!(cipher.process_bytes(&plaintext[..5], &mut encrypted)?, 0);
//! assert_eq!(cipher.process_bytes(&plaintext[5..], &mut encrypted)?, 16);
//! assert_eq!(cipher.do_final(&mut [])?, 0);
//! assert_eq!(encrypted, expected);
//!
//! cipher.init(CipherDirection::Decrypt, &params)?;
//! let mut recovered = [0u8; 16];
//! assert_eq!(cipher.process_bytes(&encrypted, &mut recovered)?, 16);
//! assert_eq!(cipher.do_final(&mut [])?, 0);
//! assert_eq!(recovered, plaintext);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod buffered_block_cipher;
mod buffered_ies_cipher;
mod buffered_stream_cipher;

pub use buffered_block_cipher::BufferedBlockCipher;
pub use buffered_ies_cipher::BufferedIesCipher;
pub use buffered_stream_cipher::BufferedStreamCipher;
