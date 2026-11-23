use std::io::{self, Read, Write};

use tc_openpgp_packet::{DecodingConfig, LiteralData};

use crate::{PgpKeyPair, PgpPublicKey};

#[cfg(feature = "encryption")]
mod x25519;

#[cfg(feature = "encryption")]
pub(crate) use x25519::X25519EncryptedMessages;

/// Encrypts and decrypts OpenPGP messages for one or more recipients.
pub trait PgpEncryptedMessageProvider: Send + Sync {
    fn encrypt(
        &self,
        recipient: &PgpPublicKey,
        data: &LiteralData,
        output: &mut dyn Write,
    ) -> io::Result<()>;

    /// Encrypts one message using a shared session key wrapped for each recipient.
    fn encrypt_to_many(
        &self,
        recipients: &[&PgpPublicKey],
        data: &LiteralData,
        output: &mut dyn Write,
    ) -> io::Result<()> {
        match recipients {
            [recipient] => self.encrypt(recipient, data, output),
            [] => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected at least one recipient",
            )),
            _ => Err(io::ErrorKind::Unsupported.into()),
        }
    }

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
