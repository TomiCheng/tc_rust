//! ECNR，橢圓曲線版的 Nyberg-Rueppel 簽章（IEEE P1363 的 ECSP-NR／ECVP-NR），移植自
//! Bouncy Castle 的 `ECNRSigner`，實作 `tc_dsa` 的 `Dsa` 與 `DsaInit`。金鑰來自 `tc_ec_key`，
//! 每個簽章的 k 由 `tc_dsa` 的 k 計算器提供。
//!
//! 和 ECDSA 一樣只簽雜湊；要簽整則訊息，交給 `tc_dsa` 的 `DsaDigestSigner`：
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dsa::{DsaDigestSigner, RandomDsaKCalculator};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_ecnr::EcnrSigner;
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//! use tc_sha::Sha256Digest;
//! use tc_signer::{Signer, SignerInit};
//!
//! // Alice 在常數時間的曲線上產生金鑰對。
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>>::new();
//! generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // 她以私鑰簽訊息的 SHA-256，k 每次隨機抽取……
//! let ecnr = || EcnrSigner::new(RandomDsaKCalculator::new(rand::rng()));
//! let mut signer = DsaDigestSigner::new(ecnr(), Sha256Digest::new());
//! signer.init(&private_key)?;
//! signer.update(b"attack at dawn")?;
//! let mut signature = vec![0; signer.max_signature_size()];
//! let length = signer.generate_signature(&mut signature)?;
//!
//! // ……Bob 以她的公鑰驗證。
//! let mut verifier = DsaDigestSigner::new(ecnr(), Sha256Digest::new());
//! verifier.init(&public_key)?;
//! verifier.update(b"attack at dawn")?;
//! assert!(verifier.verify_signature(&signature[..length])?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod error;
mod signer;

pub use error::EcnrError;
pub use signer::EcnrSigner;
