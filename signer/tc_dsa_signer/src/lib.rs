//! DSA（FIPS 186），移植自 Bouncy Castle：參數、驗證參數、公私鑰、金鑰對產生器、FIPS 186-2
//! 與 186-3 的參數產生器，以及實作 `tc_dsa` 的 `Dsa` 的 `DsaSigner`。要簽整則訊息、編碼簽章時，
//! 用 `tc_dsa` 的 `DsaDigestSigner` 包起來。
//!
//! ```no_run
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dsa::{DsaDigestSigner, HMacDsaKCalculator};
//! use tc_dsa_signer::{
//!     DsaGroupGenerationParams, DsaGroupGenerator, DsaKeyGenerationParams, DsaKeyPairGenerator,
//!     DsaSigner,
//! };
//! use tc_sha::Sha256Digest;
//! use tc_signer::{Signer, SignerInit};
//!
//! // 參數：FIPS 186-3 的 L = 2048、N = 256，以 SHA-256 產生；要數秒到數十秒。
//! let mut group_generator = DsaGroupGenerator::with_digest(rand::rng(), Sha256Digest::new());
//! group_generator.init_fips186_3(&DsaGroupGenerationParams::new(2048, 256, 80))?;
//! let params = group_generator.generate_group()?;
//!
//! // 簽章者的金鑰對：x 留在本地、drop 時清除，y 交給驗章者。
//! let mut generator = DsaKeyPairGenerator::new(rand::rng());
//! generator.init(&DsaKeyGenerationParams::new(params))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // 簽章：整則訊息以 SHA-256 雜湊，k 照 RFC 6979 由私鑰與雜湊決定，簽章編成 DER。
//! let dsa = || DsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
//! let mut signer = DsaDigestSigner::new(dsa(), Sha256Digest::new());
//! signer.init(&private_key)?;
//! signer.update(b"hello")?;
//! let mut signature = vec![0; signer.max_signature_size()];
//! let length = signer.generate_signature(&mut signature)?;
//!
//! // 驗章：收到別人的公鑰時先檢查，再以同一個雜湊驗證。
//! public_key.validate()?;
//! let mut verifier = DsaDigestSigner::new(dsa(), Sha256Digest::new());
//! verifier.init(&public_key)?;
//! verifier.update(b"hello")?;
//! assert!(verifier.verify_signature(&signature[..length])?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod dsa_error;
mod error;
mod group_generator;
mod key_pair_generator;
mod math;
mod params;
mod signer;

pub use dsa_error::DsaError;
pub use error::DsaSignerError;
pub use group_generator::DsaGroupGenerator;
pub use key_pair_generator::DsaKeyPairGenerator;
pub use params::{
    DsaGroupGenerationParams, DsaKeyGenerationParams, DsaParameters, DsaPrivateKey, DsaPublicKey,
    DsaValidationParameters,
};
pub use signer::DsaSigner;
