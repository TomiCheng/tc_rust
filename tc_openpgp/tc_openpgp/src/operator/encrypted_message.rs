use std::io::{self, Read, Write};

use tc_openpgp_packet::{DecodingConfig, LiteralData};

use crate::{PgpKeyPair, PgpPublicKey};

#[cfg(feature = "encryption")]
mod x25519;

#[cfg(feature = "legacy-encryption")]
mod rsa;

#[cfg(any(feature = "encryption", feature = "legacy-encryption"))]
pub(crate) struct DefaultEncryptedMessages {
    pub(crate) algo: std::sync::Arc<dyn tc_algo::Algo>,
}

#[cfg(any(feature = "encryption", feature = "legacy-encryption"))]
impl PgpEncryptedMessageProvider for DefaultEncryptedMessages {
    fn encrypt(
        &self,
        recipient: &PgpPublicKey,
        data: &LiteralData,
        output: &mut dyn Write,
    ) -> io::Result<()> {
        self.encrypt_to_many(&[recipient], data, output)
    }

    fn encrypt_to_many(
        &self,
        _recipients: &[&PgpPublicKey],
        _data: &LiteralData,
        _output: &mut dyn Write,
    ) -> io::Result<()> {
        #[cfg(feature = "encryption")]
        {
            x25519::X25519EncryptedMessages {
                algo: self.algo.clone(),
            }
            .encrypt_to_many(_recipients, _data, _output)
        }
        #[cfg(not(feature = "encryption"))]
        Err(io::ErrorKind::Unsupported.into())
    }

    fn decrypt(
        &self,
        recipient: &PgpKeyPair,
        input: &mut dyn Read,
        config: &DecodingConfig,
    ) -> io::Result<LiteralData> {
        use tc_openpgp_packet::PublicKeyAlgorithmTag;

        match recipient.public().algorithm() {
            #[cfg(feature = "legacy-encryption")]
            PublicKeyAlgorithmTag::RsaGeneral | PublicKeyAlgorithmTag::RsaEncrypt => {
                rsa::decrypt(&*self.algo, recipient, input, config)
            }
            #[cfg(feature = "encryption")]
            PublicKeyAlgorithmTag::X25519 => x25519::X25519EncryptedMessages {
                algo: self.algo.clone(),
            }
            .decrypt(recipient, input, config),
            _ => Err(io::ErrorKind::Unsupported.into()),
        }
    }
}

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

    /// Returns literal data only after checking the complete encrypted message.
    /// With the legacy-encryption feature the built-in provider can read
    /// addressed v3 RSA PKESK with v1 AES-CFB SEIPD, using a v4 RSA CRT key pair.
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
