use std::io::{self, Read, Write};

use tc_openpgp_packet::{DecodingConfig, LiteralData};

use crate::{PgpCertificate, PgpKeyPair, PgpPublicKey};

#[cfg(any(feature = "encryption", feature = "legacy-encryption"))]
mod payload;
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

    #[cfg(feature = "encryption")]
    fn sign_and_encrypt(
        &self,
        signer: &PgpKeyPair,
        recipients: &[&PgpCertificate],
        data: &LiteralData,
        creation_time: u32,
        output: &mut dyn Write,
    ) -> io::Result<()> {
        use crate::PgpEncryptionPurpose;
        use crate::operator::{
            detached_signature::DefaultDetachedSignatures, serializer::v6_fingerprint,
        };

        if recipients.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected at least one recipient",
            ));
        }
        let mut subkeys = Vec::new();
        let mut intended = Vec::new();
        for certificate in recipients {
            let key = certificate
                .encryption_key_at(creation_time, PgpEncryptionPurpose::Communications)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "recipient has no usable encryption subkey",
                    )
                })?;
            let fingerprint = v6_fingerprint(&*self.algo, certificate.primary_key())?;
            // RFC 9580 Section 5.2.3.36, critical hashed subpacket.
            intended.extend_from_slice(&[34, 0x80 | 35, 6]);
            intended.extend_from_slice(&fingerprint);
            subkeys.push(key);
        }

        let signatures = DefaultDetachedSignatures {
            algo: self.algo.clone(),
        };
        let signature = signatures.ed25519().sign_data(
            signer,
            &mut data.data(),
            creation_time,
            tc_openpgp_packet::SignatureTypeId::BINARY_DOCUMENT,
            &intended,
        )?;
        let mut counter = CountingWriter(0);
        signatures.write_signed_message(signer.public(), data, &signature, &mut counter)?;
        self.x25519().encrypt_payload(
            &subkeys,
            counter.0,
            |out| signatures.write_signed_message(signer.public(), data, &signature, out),
            output,
        )
    }

    #[cfg(feature = "encryption")]
    fn decrypt_and_verify(
        &self,
        recipient: &PgpKeyPair,
        certificate: &PgpCertificate,
        signer: &PgpPublicKey,
        input: &mut dyn Read,
        config: &DecodingConfig,
    ) -> io::Result<LiteralData> {
        use crate::operator::{
            detached_signature::DefaultDetachedSignatures, serializer::v6_fingerprint,
        };

        let actual = v6_fingerprint(&*self.algo, recipient.public())?;
        let mut bound = false;
        for subkey in certificate.subkeys() {
            if v6_fingerprint(&*self.algo, subkey.key())? == actual {
                bound = true;
                break;
            }
        }
        if !bound {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recipient key is not bound to the supplied certificate",
            ));
        }

        let fingerprint = v6_fingerprint(&*self.algo, certificate.primary_key())?;
        let plaintext = self.x25519().decrypt_payload(recipient, input, config)?;
        let mut packets = plaintext.as_slice();
        let signatures = DefaultDetachedSignatures {
            algo: self.algo.clone(),
        };
        let inner_config = DecodingConfig {
            header_format: None,
            ..*config
        };
        let literal = signatures.verify_signed_message(
            signer,
            &mut packets,
            &inner_config,
            Some(&fingerprint),
        )?;
        if !packets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing packets after signed message",
            ));
        }
        Ok(literal)
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

    /// Signs and encrypts a binary document to the current communications subkey of each certificate.
    fn sign_and_encrypt(
        &self,
        _signer: &PgpKeyPair,
        _recipients: &[&PgpCertificate],
        _data: &LiteralData,
        _creation_time: u32,
        _output: &mut dyn Write,
    ) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Decrypts and verifies a v6 signed message bound to the recipient's primary key.
    /// The caller establishes trust in both the recipient certificate and signer key.
    fn decrypt_and_verify(
        &self,
        _recipient: &PgpKeyPair,
        _certificate: &PgpCertificate,
        _signer: &PgpPublicKey,
        _input: &mut dyn Read,
        _config: &DecodingConfig,
    ) -> io::Result<LiteralData> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Returns literal data only after checking the complete encrypted message.
    /// ZIP and ZLIB share a cumulative expansion limit of 64 MiB or the
    /// configured maximum packet body size, whichever is lower, and four layers.
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

#[cfg(feature = "encryption")]
impl DefaultEncryptedMessages {
    fn x25519(&self) -> x25519::X25519EncryptedMessages {
        x25519::X25519EncryptedMessages {
            algo: self.algo.clone(),
        }
    }
}

#[cfg(feature = "encryption")]
struct CountingWriter(u64);

#[cfg(feature = "encryption")]
impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
