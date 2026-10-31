//! DSTU 4145-2002 簽章，移植自 Bouncy Castle 的 `Dstu4145Signer` 與
//! `Dstu4145KeyPairGenerator`：GF(2^m) 橢圓曲線上的簽章，實作 `tc_dsa` 的 `Dsa`，經
//! `DsaDigestSigner` 接上 `tc_signer`。
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dsa::{DsaDigestSigner, PlainDsaEncoding, RandomDsaKCalculator};
//! use tc_dstu4145::{Dstu4145KeyPairGenerator, Dstu4145Signer};
//! use tc_ec_key::EcKeyGenerationParams;
//! use tc_f2m_curve::F2mCtCurve;
//! use tc_f2m_curve::named_curves::SECT163R2;
//! use tc_sha::Sha256Digest;
//! use tc_signer::{Signer, SignerInit};
//!
//! // 金鑰對：公鑰是 −d·G。實務上用 DSTU 4145 的曲線，這裡借 SEC 2 的一條。
//! let curve = SECT163R2.ct_curve();
//! let g = SECT163R2.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = Dstu4145KeyPairGenerator::<&F2mCtCurve>::new();
//! generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // 以隨機的 e 簽章，r ‖ s 不經 DER。
//! let dstu = || Dstu4145Signer::new(RandomDsaKCalculator::new(rand::rng()));
//! let mut signer = DsaDigestSigner::with_encoding(dstu(), Sha256Digest::new(), PlainDsaEncoding);
//! signer.init(&private_key)?;
//! signer.update(b"hello")?;
//! let mut signature = vec![0; signer.max_signature_size()];
//! let length = signer.generate_signature(&mut signature)?;
//!
//! let mut verifier = DsaDigestSigner::with_encoding(dstu(), Sha256Digest::new(), PlainDsaEncoding);
//! verifier.init(&public_key)?;
//! verifier.update(b"hello")?;
//! assert!(verifier.verify_signature(&signature[..length])?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod curve;
mod error;
mod key_pair_generator;
mod signer;

pub use curve::Dstu4145Curve;
pub use error::Dstu4145Error;
pub use key_pair_generator::Dstu4145KeyPairGenerator;
pub use signer::Dstu4145Signer;
