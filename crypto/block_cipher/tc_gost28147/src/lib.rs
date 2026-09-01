//! GOST 28147-89 block cipher.
//!
//! A 32-round Feistel cipher over a 64-bit block with a 256-bit key. Unusually,
//! the S-box is a parameter rather than part of the algorithm, so the same key
//! under two tables gives two different ciphers; the standardized tables live
//! in [`s_box`]. There is no key expansion: the eight key words are the
//! schedule, and only the order they are used in tells the two directions
//! apart.
//!
//! Engines are initialised through
//! [`KeyWithSBoxParams`](tc_params::KeyWithSBoxParams). [`KeyWithSBox`] is the
//! ready-made implementation, defaulting to [`s_box::DEFAULT`] as Bouncy
//! Castle does.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_gost28147::{BLOCK_BYTES, Gost28147Engine, KeyWithSBox, s_box};
//!
//! let key = [0u8; 32];
//! let plaintext = [0u8; BLOCK_BYTES];
//!
//! // 換一張表就是換一個密碼:同金鑰同明文會得到不同密文。
//! let mut ciphertext = [[0u8; BLOCK_BYTES]; 2];
//! for (params, output) in [
//!     KeyWithSBox::new(&key),
//!     KeyWithSBox::with_s_box(&key, &s_box::E_A),
//! ]
//! .into_iter()
//! .zip(&mut ciphertext)
//! {
//!     let mut engine = Gost28147Engine::new();
//!     engine.init(CipherDirection::Encrypt, &params)?;
//!     engine.process_block(&plaintext, output)?;
//! }
//! assert_ne!(ciphertext[0], ciphertext[1]);
//!
//! let params = KeyWithSBox::new(&key);
//! let mut engine = Gost28147Engine::new();
//! engine.init(CipherDirection::Decrypt, &params)?;
//!
//! let mut recovered = [0u8; BLOCK_BYTES];
//! engine.process_block(&ciphertext[0], &mut recovered)?;
//! assert_eq!(recovered, plaintext);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod cipher;
mod engine;
mod params;

pub mod s_box;

pub use engine::Gost28147Engine;
pub use params::KeyWithSBox;

/// GOST 28147 block length in bytes (64 bits).
pub const BLOCK_BYTES: usize = 8;
/// GOST 28147 key length in bytes (256 bits).
pub const KEY_BYTES: usize = 32;
