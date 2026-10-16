//! Elliptic-curve keys, after Bouncy Castle's `ECPrivateKeyParameters` and
//! `ECPublicKeyParameters`, shared by ECDH, ECDSA and the rest. The generator G stands for
//! BC's `ECDomainParameters`: a point carries its curve, and the curve its order and
//! cofactor.
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_fp_curve_v2::FpCtCurve;
//! use tc_fp_curve_v2::named_curves::SECP256R1;
//!
//! // A constant-time curve, since d is secret, and its generator G.
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//!
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>>::new();
//! generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
//! // Q goes to the other party; d stays here and is wiped when dropped.
//! let (public_key, private_key) = generator.generate_key_pair()?;
//! # Ok::<(), tc_ec::EcError>(())
//! ```

#![no_std]

mod error;
mod key_pair_generator;
mod params;

pub use error::EcError;
pub use key_pair_generator::EcKeyPairGenerator;
pub use params::{EcKeyGenerationParams, EcPrivateKey, EcPublicKey};
