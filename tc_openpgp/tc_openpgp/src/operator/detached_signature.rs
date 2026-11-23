use std::io::{self, Read};

use tc_openpgp_packet::SignaturePacket;
#[cfg(any(feature = "cfrg-curves", feature = "rsa"))]
use tc_openpgp_packet::{SignatureTypeId, SignatureVersion};

use crate::{PgpKeyPair, PgpPublicKey};

#[cfg(feature = "cfrg-curves")]
mod ed25519;
#[cfg(feature = "rsa")]
mod rsa;

#[cfg(feature = "cfrg-curves")]
pub(crate) use ed25519::Ed25519DetachedSignatures;
#[cfg(feature = "secret-key")]
pub(super) use ed25519::matching_private_key as matching_ed25519_key;

#[cfg(any(feature = "cfrg-curves", feature = "rsa"))]
pub(crate) struct DefaultDetachedSignatures {
    pub(crate) algo: std::sync::Arc<dyn tc_algo::Algo>,
}

#[cfg(feature = "cfrg-curves")]
impl DefaultDetachedSignatures {
    fn ed25519(&self) -> Ed25519DetachedSignatures {
        Ed25519DetachedSignatures {
            algo: self.algo.clone(),
        }
    }
}

#[cfg(any(feature = "cfrg-curves", feature = "rsa"))]
impl PgpDetachedSignatureProvider for DefaultDetachedSignatures {
    fn sign(
        &self,
        _keys: &PgpKeyPair,
        _document: &mut dyn Read,
        _creation_time: u32,
    ) -> io::Result<SignaturePacket> {
        #[cfg(feature = "cfrg-curves")]
        {
            self.ed25519().sign(_keys, _document, _creation_time)
        }
        #[cfg(not(feature = "cfrg-curves"))]
        Err(io::ErrorKind::Unsupported.into())
    }

    fn verify(
        &self,
        key: &PgpPublicKey,
        document: &mut dyn Read,
        signature: &SignaturePacket,
    ) -> io::Result<bool> {
        match signature.version() {
            #[cfg(feature = "rsa")]
            SignatureVersion::V4 => rsa::verify(&*self.algo, key, document, signature),
            #[cfg(feature = "cfrg-curves")]
            SignatureVersion::V6 => self.ed25519().verify(key, document, signature),
            #[allow(unreachable_patterns)]
            _ => Err(io::ErrorKind::Unsupported.into()),
        }
    }
}

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

#[cfg(any(feature = "cfrg-curves", feature = "rsa"))]
fn document_is_text(packet: &SignaturePacket) -> io::Result<bool> {
    match packet.signature_type() {
        SignatureTypeId::BINARY_DOCUMENT => Ok(false),
        SignatureTypeId::CANONICAL_TEXT_DOCUMENT => Ok(true),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "expected a document signature",
        )),
    }
}

#[cfg(any(feature = "cfrg-curves", feature = "rsa"))]
fn read_document(
    input: &mut dyn Read,
    text: bool,
    mut update: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut bytes = [0; 4096];
    let mut canonical = Vec::new();
    let mut previous_cr = false;
    loop {
        let count = match input.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let mut chunk = &bytes[..count];
        if text {
            canonical.clear();
            for &byte in chunk {
                match byte {
                    b'\n' if previous_cr => {}
                    b'\r' | b'\n' => canonical.extend_from_slice(b"\r\n"),
                    _ => canonical.push(byte),
                }
                previous_cr = byte == b'\r';
            }
            chunk = &canonical;
        }
        update(chunk)?;
    }
}
