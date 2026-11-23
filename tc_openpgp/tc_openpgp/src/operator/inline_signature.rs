use std::io::{self, Read, Write};

use crate::{PgpKeyPair, PgpPublicKey};
use tc_openpgp_packet::{DecodingConfig, LiteralData};

#[cfg(feature = "cfrg-curves")]
mod ed25519;

/// Creates and verifies a single-signer OpenPGP inline-signed message.
pub trait PgpInlineSignatureProvider: Send + Sync {
    /// Writes a v6 Ed25519 binary document signature around the supplied literal packet.
    fn sign(
        &self,
        keys: &PgpKeyPair,
        literal: &LiteralData,
        creation_time: u32,
        output: &mut dyn Write,
    ) -> io::Result<()>;

    /// Reads exactly one message, leaving subsequent bytes in the input.
    ///
    /// Returns its literal packet after verification. The signature covers the
    /// document bytes, and the caller establishes trust in the supplied key.
    /// The literal packet's filename, timestamp and format are unauthenticated.
    fn verify(
        &self,
        key: &PgpPublicKey,
        input: &mut dyn Read,
        config: &DecodingConfig,
    ) -> io::Result<LiteralData>;
}

pub(crate) struct EmptyInlineSignatureProvider;

impl PgpInlineSignatureProvider for EmptyInlineSignatureProvider {
    fn sign(&self, _: &PgpKeyPair, _: &LiteralData, _: u32, _: &mut dyn Write) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn verify(
        &self,
        _: &PgpPublicKey,
        _: &mut dyn Read,
        _: &DecodingConfig,
    ) -> io::Result<LiteralData> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
