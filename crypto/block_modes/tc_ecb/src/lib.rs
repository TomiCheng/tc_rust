//! Electronic Codebook (ECB) mode.
//!
//! ECB applies the underlying block cipher independently to every block. It
//! requires no IV, chaining state, allocation, or additional initialization
//! parameters. Identical plaintext blocks produce identical ciphertext blocks,
//! so ECB is unsuitable for most protocols and is provided primarily for
//! compatibility and composition with algorithms that require the raw block
//! permutation.
//!
//! ```
//! use tc_aes::{AesEngine, BLOCK_BYTES};
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_ecb::EcbBlockCipher;
//! use tc_params::KeyRef;
//!
//! let key = [0u8; 16];
//! let mut mode = EcbBlockCipher::new(AesEngine::new());
//! mode.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//!
//! let mut output = [0u8; BLOCK_BYTES];
//! mode.process_block(&[0u8; BLOCK_BYTES], &mut output)?;
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod mode;

pub use mode::EcbBlockCipher;
