use std::io::{self, Write};

use tc_openpgp_packet::{ArmorKind, AsciiArmor, DecodingConfig, SignaturePacket};

use crate::{PgpKeyPair, PgpPublicKey};

#[cfg(feature = "cfrg-curves")]
mod v6;
#[cfg(feature = "cfrg-curves")]
pub(crate) use v6::V6Certificates;
#[cfg(feature = "secret-key")]
pub(super) use v6::encode_with_keys;

/// A v6 transferable public key with verified self-signatures and subkey bindings.
pub struct PgpCertificate {
    primary_key: PgpPublicKey,
    direct_signature: SignaturePacket,
    user_ids: Vec<PgpCertifiedUserId>,
    subkeys: Vec<PgpCertifiedSubkey>,
}

impl PgpCertificate {
    pub fn primary_key(&self) -> &PgpPublicKey {
        &self.primary_key
    }

    pub fn direct_signature(&self) -> &SignaturePacket {
        &self.direct_signature
    }

    pub fn user_ids(&self) -> &[PgpCertifiedUserId] {
        &self.user_ids
    }

    pub fn subkeys(&self) -> &[PgpCertifiedSubkey] {
        &self.subkeys
    }
}

/// A UTF-8 User ID and its primary-key self-signature.
pub struct PgpCertifiedUserId {
    value: String,
    signature: SignaturePacket,
}

impl PgpCertifiedUserId {
    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn signature(&self) -> &SignaturePacket {
        &self.signature
    }
}

/// An encryption subkey and its binding signature.
pub struct PgpCertifiedSubkey {
    key: PgpPublicKey,
    signature: SignaturePacket,
}

impl PgpCertifiedSubkey {
    pub fn key(&self) -> &PgpPublicKey {
        &self.key
    }

    pub fn signature(&self) -> &SignaturePacket {
        &self.signature
    }
}

/// Creates, encodes and validates transferable public keys.
pub trait PgpCertificateProvider: Send + Sync {
    /// Issues a direct-key self-signature and signs each supplied User ID and subkey.
    fn create(
        &self,
        primary: &PgpKeyPair,
        user_ids: &[&str],
        subkeys: &[&PgpPublicKey],
        creation_time: u32,
    ) -> io::Result<PgpCertificate>;

    /// Writes a transferable public key in binary packet format.
    fn encode_to(&self, certificate: &PgpCertificate, output: &mut dyn Write) -> io::Result<()>;

    /// Reads exactly one certificate and verifies its self-signatures and bindings.
    ///
    /// The built-in provider supports a v6 Ed25519 primary key, a single direct
    /// signature, and one self-signature per UTF-8 identity and X25519 subkey.
    /// The caller establishes identity trust and evaluates expiration and usage policy.
    fn decode(&self, bytes: &[u8], config: &DecodingConfig) -> io::Result<PgpCertificate>;

    fn encode(&self, certificate: &PgpCertificate) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        self.encode_to(certificate, &mut output)?;
        Ok(output)
    }

    fn encode_armored(&self, certificate: &PgpCertificate) -> io::Result<String> {
        AsciiArmor::encode(ArmorKind::PublicKey, &self.encode(certificate)?)
    }

    fn decode_armored(&self, text: &str, config: &DecodingConfig) -> io::Result<PgpCertificate> {
        self.decode(&AsciiArmor::decode(ArmorKind::PublicKey, text)?, config)
    }
}

pub(crate) struct EmptyCertificateProvider;

impl PgpCertificateProvider for EmptyCertificateProvider {
    fn create(
        &self,
        _: &PgpKeyPair,
        _: &[&str],
        _: &[&PgpPublicKey],
        _: u32,
    ) -> io::Result<PgpCertificate> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn encode_to(&self, _: &PgpCertificate, _: &mut dyn Write) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn decode(&self, _: &[u8], _: &DecodingConfig) -> io::Result<PgpCertificate> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
