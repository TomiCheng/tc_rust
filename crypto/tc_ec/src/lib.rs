//! Elliptic-curve domain parameters and keys, after Bouncy Castle's `ECDomainParameters`,
//! `ECPrivateKeyParameters` and `ECPublicKeyParameters`, shared by ECDH, ECDSA and the
//! rest.

#![no_std]

mod ec_domain;
mod ec_private_key;
mod ec_public_key;

pub use ec_domain::EcDomain;
pub use ec_private_key::EcPrivateKey;
pub use ec_public_key::EcPublicKey;
