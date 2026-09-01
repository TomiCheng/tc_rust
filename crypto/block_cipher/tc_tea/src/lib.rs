//! TEA and XTEA block ciphers.
//!
//! Both take a 128-bit key and a 64-bit block over thirty-two rounds driven by
//! the golden-ratio constant `delta`. XTEA differs in its key schedule: rather
//! than using the same two key words every round, it lets `delta`'s running sum
//! select which word each Feistel half sees, which is what repairs TEA's
//! related-key weakness. The two are not interchangeable.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_params::KeyRef;
//! use tc_tea::{BLOCK_BYTES, KEY_BYTES, TeaEngine, XteaEngine};
//!
//! let key = [0u8; KEY_BYTES];
//! let plaintext = [0u8; BLOCK_BYTES];
//!
//! let mut engine = TeaEngine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//!
//! let mut ciphertext = [0u8; BLOCK_BYTES];
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [0x41, 0xea, 0x3a, 0x0a, 0x94, 0xba, 0xa9, 0x40]);
//!
//! engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
//!
//! let mut recovered = [0u8; BLOCK_BYTES];
//! engine.process_block(&ciphertext, &mut recovered)?;
//! assert_eq!(recovered, plaintext);
//!
//! // 同樣的金鑰與明文,XTEA 得到的是另一組密文。
//! let mut engine = XteaEngine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [0xde, 0xe9, 0xd4, 0xd8, 0xf7, 0x13, 0x1e, 0xd9]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod cipher;
mod engine;

pub use engine::{TeaEngine, XteaEngine};

/// TEA and XTEA block length in bytes (64 bits).
pub const BLOCK_BYTES: usize = 8;
/// TEA and XTEA key length in bytes (128 bits).
pub const KEY_BYTES: usize = 16;
