//! Elliptic-curve keys, after Bouncy Castle's `ECPrivateKeyParameters` and
//! `ECPublicKeyParameters`, shared by ECDH, ECDSA and the rest. The generator G stands for
//! BC's `ECDomainParameters`: a point carries its curve, and the curve its order and
//! cofactor.

#![no_std]

mod error;
mod key_pair_generator;
mod params;

pub use error::EcError;
pub use key_pair_generator::EcKeyPairGenerator;
pub use params::{EcKeyGenerationParams, EcPrivateKey, EcPublicKey};
