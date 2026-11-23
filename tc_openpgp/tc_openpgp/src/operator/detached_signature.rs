use std::io::{self, Read};

use tc_openpgp_packet::SignaturePacket;

use crate::{PgpKeyPair, PgpPublicKey};

#[cfg(feature = "cfrg-curves")]
mod ed25519;

#[cfg(feature = "cfrg-curves")]
pub(crate) use ed25519::Ed25519DetachedSignatures;

/// Signs and verifies detached document signatures.
pub trait PgpDetachedSignatureProvider: Send + Sync {
    fn sign(
        &self,
        keys: &PgpKeyPair,
        document: &mut dyn Read,
        creation_time: u32,
    ) -> io::Result<SignaturePacket>;

    /// Checks a signature using the supplied key. The caller establishes the key's trust.
    fn verify(
        &self,
        key: &PgpPublicKey,
        document: &mut dyn Read,
        signature: &SignaturePacket,
    ) -> io::Result<bool>;
}

pub(crate) struct EmptyDetachedSignatureProvider;

impl PgpDetachedSignatureProvider for EmptyDetachedSignatureProvider {
    fn sign(&self, _: &PgpKeyPair, _: &mut dyn Read, _: u32) -> io::Result<SignaturePacket> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn verify(&self, _: &PgpPublicKey, _: &mut dyn Read, _: &SignaturePacket) -> io::Result<bool> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
