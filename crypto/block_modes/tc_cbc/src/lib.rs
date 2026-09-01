//! Cipher Block Chaining (CBC) mode.
//!
//! CBC XORs each plaintext block with the preceding ciphertext block before
//! encryption. The first block uses an initialization vector (IV). This crate
//! processes complete blocks only; padding belongs to a separate layer.
//!
//! [`FixedCbcBlockCipher`] stores its chaining state in `[u8; N]` and works
//! without allocation. The default `alloc` feature additionally provides
//! `CbcBlockCipher`, whose state size is selected from the cipher at runtime.
//!
//! ```
//! use tc_aes::{AesEngine, BLOCK_BYTES};
//! use tc_cbc::{CbcBlockCipher, Params};
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_params::{KeyParams, KeyRef};
//!
//! let key = [0u8; 16];
//! let iv = [0u8; BLOCK_BYTES];
//! let key_params = KeyRef::new(&key);
//! let params = Params::<dyn KeyParams>::with_iv(&key_params, &iv);
//! let mut mode = CbcBlockCipher::new(AesEngine::new());
//! mode.init(CipherDirection::Encrypt, &params)?;
//!
//! let mut output = [0u8; BLOCK_BYTES];
//! mode.process_block(&[0u8; BLOCK_BYTES], &mut output)?;
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod fixed_mode;
#[cfg(feature = "alloc")]
mod mode;
mod params;

pub use fixed_mode::FixedCbcBlockCipher;
#[cfg(feature = "alloc")]
pub use mode::CbcBlockCipher;
pub use params::Params;
