//! ECDSA; a rewrite of `tc_ecdsa` on `tc_ec_core`.
//!
//! Alice signs a message with her private key, and anyone with her public key can check it:
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_digest::Digest;
//! use tc_dsa::{Dsa, DsaInit, HMacDsaKCalculator};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_ecdsa_v2::EcdsaSigner;
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//! use tc_sha::Sha256Digest;
//!
//! // Alice makes a key pair on a constant-time curve.
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>>::new();
//! generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // ECDSA signs the hash of the message, which comes first.
//! let mut digest = Sha256Digest::new();
//! digest.update(b"attack at dawn");
//! let mut hash = [0; 32];
//! digest.do_final(&mut hash);
//!
//! // She signs with her private key, k drawn as RFC 6979 does...
//! let mut signer = EcdsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
//! signer.init(&private_key)?;
//! let (r, s) = signer.generate_signature(&hash)?;
//!
//! // ...and Bob checks (r, s) with her public key.
//! signer.init(&public_key)?;
//! assert!(signer.verify_signature(&hash, &r, &s)?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod error;
mod signer;

pub use error::EcdsaError;
pub use signer::EcdsaSigner;
