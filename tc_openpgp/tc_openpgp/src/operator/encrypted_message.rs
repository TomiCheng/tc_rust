use std::io::{self, Read, Write};

use tc_openpgp_packet::{DecodingConfig, LiteralData};

use crate::{PgpKeyPair, PgpPublicKey};

#[cfg(feature = "encryption")]
mod x25519;

#[cfg(feature = "encryption")]
pub(crate) use x25519::X25519EncryptedMessages;

/// Encrypts and decrypts OpenPGP messages for a single recipient.
pub trait PgpEncryptedMessageProvider: Send + Sync {
    fn encrypt(
        &self,
        recipient: &PgpPublicKey,
        data: &LiteralData,
        output: &mut dyn Write,
    ) -> io::Result<()>;

    /// Returns the literal data after authenticating the complete encrypted message.
    fn decrypt(
        &self,
        recipient: &PgpKeyPair,
        input: &mut dyn Read,
        config: &DecodingConfig,
    ) -> io::Result<LiteralData>;
}

pub(crate) struct EmptyEncryptedMessageProvider;

impl PgpEncryptedMessageProvider for EmptyEncryptedMessageProvider {
    fn encrypt(&self, _: &PgpPublicKey, _: &LiteralData, _: &mut dyn Write) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn decrypt(
        &self,
        _: &PgpKeyPair,
        _: &mut dyn Read,
        _: &DecodingConfig,
    ) -> io::Result<LiteralData> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
