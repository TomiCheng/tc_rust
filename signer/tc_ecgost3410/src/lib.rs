//! GOST R 34.10-2001／2012 的 EC 簽章，移植自 Bouncy Castle 的 `ECGost3410Signer`，實作
//! `tc_dsa` 的 `Dsa`。金鑰來自 `tc_ec_key`；要簽整則訊息時，用 `tc_dsa` 的
//! `Gost3410DigestSigner` 包上 GOST R 34.11 雜湊。
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_bigint::PaddedBigUint;
//! use tc_dsa::{Gost3410DigestSigner, RandomDsaKCalculator};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_ecgost3410::EcGost3410Signer;
//! use tc_fp_curve::{FpCtCurve, FpField};
//! use tc_gost3411::Gost3411_2012_256Digest;
//! use tc_signer::{Signer, SignerInit};
//!
//! # use num_traits::Num;
//! // GOST R 34.10-2001 CryptoPro-A 參數（RFC 4357）。
//! let int = |text: &str| PaddedBigUint::from_str_radix(text, 10).unwrap();
//! let field = FpField::new(int(
//!     "115792089237316195423570985008687907853269984665640564039457584007913129639319",
//! ))?;
//! let curve = FpCtCurve::new(
//!     &field,
//!     &int("115792089237316195423570985008687907853269984665640564039457584007913129639316"),
//!     &int("166"),
//!     Some(int("115792089237316195423570985008687907853073762908499243225378155805079068850323")),
//!     Some(int("1")),
//! )?;
//! let g = curve.create_point(
//!     &int("1"),
//!     &int("64033881142927202683649881450433473985931760268884941288852745803908878638612"),
//! )?;
//!
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>>::new();
//! generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // 以隨機的 k 簽章；簽章是 s ‖ r。
//! let gost = || EcGost3410Signer::new(RandomDsaKCalculator::new(rand::rng()));
//! let mut signer = Gost3410DigestSigner::new(gost(), Gost3411_2012_256Digest::default());
//! signer.init(&private_key)?;
//! signer.update(b"hello")?;
//! let mut signature = vec![0; signer.max_signature_size()];
//! let length = signer.generate_signature(&mut signature)?;
//!
//! let mut verifier = Gost3410DigestSigner::new(gost(), Gost3411_2012_256Digest::default());
//! verifier.init(&public_key)?;
//! verifier.update(b"hello")?;
//! assert!(verifier.verify_signature(&signature[..length])?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod error;
mod signer;

pub use error::EcGost3410Error;
pub use signer::EcGost3410Signer;
