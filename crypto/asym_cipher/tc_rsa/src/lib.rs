//! RSA after Bouncy Castle: key pair generation and the RSA operation, as
//! an asymmetric block cipher that the encodings, such as OAEP, wrap.
//!
//! With the `alloc` feature, which is on by default, `RsaEngine` runs an
//! `RsaKey`, whose values are all of one integer type, on the engine the
//! key and the features suit best, and `RsaKeyGenerator` generates the
//! keys. The engines it picks from, of fixed width, padded and of the
//! RustCrypto `rsa` crate, are there to take directly; the fixed-width
//! ones are all that is left with `default-features = false`, for a target
//! without an allocator.
//!
//! ```
//! # #[cfg(feature = "alloc")] {
//! use tc_asym_cipher::{
//!     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
//!     KeyPairGeneratorInit,
//! };
//! use tc_rsa_v2::{RsaBlindedEngine, RsaEngine, RsaKeyGenerationParamsOwned, RsaKeyGenerator};
//!
//! // 1. Generate a 2048-bit key pair: the public key, and the private one
//! //    with its CRT values.
//! let mut generator = RsaKeyGenerator::new();
//! generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
//! let (public, private) = generator.generate_key_pair()?;
//!
//! // 2. Encrypt a block with the public key. Raw RSA is shown here; a real
//! //    message goes through a padding, such as OAEP, first.
//! let message = b"a block of at most 255 bytes";
//! let mut engine = RsaEngine::new();
//! engine.init(CipherDirection::Encrypt, &public)?;
//! let mut ciphertext = [0; 256];
//! engine.process_block(message, &mut ciphertext)?;
//!
//! // 3. Decrypt it with the private key, blinded with the system's random
//! //    source, so that the private power never sees the ciphertext
//! //    itself. The output takes the full 256 bytes of the modulus.
//! let mut engine = RsaBlindedEngine::from_parts(RsaEngine::new(), rand::rng());
//! engine.init(CipherDirection::Decrypt, &private)?;
//! let mut plaintext = [0; 256];
//! engine.process_block(&ciphertext, &mut plaintext)?;
//! let recovered = &plaintext[256 - message.len()..];
//! # assert_eq!(recovered, message);
//! # }
//! # Ok::<(), tc_rsa_v2::RsaError>(())
//! ```

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod algorithm;
mod blinded_engine;
#[cfg(feature = "alloc")]
mod blinding_engine;
#[cfg(feature = "alloc")]
mod blinding_factor_generator;
mod block;
mod core_engine;
mod crt_engine;
#[cfg(feature = "alloc")]
mod engine;
mod error;
#[cfg(feature = "alloc")]
mod key_pair_generator;
mod params;
#[cfg(test)]
mod testing;
mod traits;
mod validation;

pub use algorithm::ALGO_NAME;
pub use blinded_engine::RsaBlindedEngine;
#[cfg(feature = "alloc")]
pub use blinding_engine::RsaBlindingEngine;
#[cfg(feature = "alloc")]
pub use blinding_factor_generator::RsaBlindingFactorGenerator;
pub use core_engine::FixedRsaCoreEngine;
#[cfg(feature = "alloc")]
pub use core_engine::PaddedRsaCoreEngine;
#[cfg(feature = "rustcrypto")]
pub use core_engine::RsaCoreEngineRustCrypto;
pub use crt_engine::FixedRsaCrtCoreEngine;
#[cfg(feature = "alloc")]
pub use crt_engine::PaddedRsaCrtCoreEngine;
#[cfg(feature = "rustcrypto")]
pub use crt_engine::RsaCrtCoreEngineRustCrypto;
#[cfg(feature = "alloc")]
pub use engine::RsaEngine;
pub use error::RsaError;
#[cfg(feature = "alloc")]
pub use key_pair_generator::RsaKeyGenerator;
#[cfg(feature = "alloc")]
pub use key_pair_generator::RsaKeyPairGenerator;
#[cfg(feature = "rustcrypto")]
pub use key_pair_generator::RsaKeyPairGeneratorRustCrypto;
#[cfg(feature = "alloc")]
pub use params::RsaBlindingParams;
#[cfg(feature = "alloc")]
pub use params::RsaKey;
#[cfg(feature = "alloc")]
pub use params::RsaKeyGenerationParamsOwned;
#[cfg(feature = "alloc")]
pub use params::RsaKeyGenerationParamsRef;
pub use params::RsaKeyOwned;
pub use params::RsaKeyRef;
#[cfg(feature = "rustcrypto")]
pub use params::RsaKeyRustCrypto;
pub use params::RsaPrivateCrtKeyOwned;
pub use params::RsaPrivateCrtKeyRef;
#[cfg(feature = "rustcrypto")]
pub use params::RsaPrivateCrtKeyRustCrypto;
pub use traits::RsaBlinding;
#[cfg(feature = "alloc")]
pub use traits::RsaKeyGenerationParams;
pub use traits::RsaKeyParams;
pub use traits::RsaPrivateCrtKeyParams;
