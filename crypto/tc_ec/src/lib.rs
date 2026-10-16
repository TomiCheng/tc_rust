//! Elliptic-curve domain parameters and keys, after Bouncy Castle's `ECDomainParameters`,
//! `ECPrivateKeyParameters` and `ECPublicKeyParameters`, shared by ECDH, ECDSA and the
//! rest.

#![no_std]

mod error;
mod key_pair_generator;
mod params;

pub use error::EcError;
pub use key_pair_generator::EcKeyPairGenerator;
pub use params::{EcDomain, EcKeyGenerationParams, EcPrivateKey, EcPublicKey};
