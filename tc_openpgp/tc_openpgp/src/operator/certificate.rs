use std::io::{self, Write};

use tc_openpgp_packet::{ArmorKind, AsciiArmor, DecodingConfig, SignaturePacket};

use crate::{PgpKeyPair, PgpPublicKey};

mod policy;
use policy::{KeySignature, current, latest};

#[cfg(feature = "cfrg-curves")]
mod v6;
#[cfg(feature = "cfrg-curves")]
pub(crate) use v6::V6Certificates;
#[cfg(feature = "secret-key")]
pub(super) use v6::encode_with_keys;

/// A v6 transferable public key with verified self-signatures and subkey bindings.
pub struct PgpCertificate {
    primary_key: PgpPublicKey,
    direct_signatures: Vec<KeySignature>,
    revocations: Vec<KeySignature>,
    user_ids: Vec<PgpCertifiedUserId>,
    subkeys: Vec<PgpCertifiedSubkey>,
}

impl PgpCertificate {
    pub fn primary_key(&self) -> &PgpPublicKey {
        &self.primary_key
    }

    /// Returns the newest verified Direct Key signature.
    pub fn direct_signature(&self) -> &SignaturePacket {
        &latest(&self.direct_signatures)
            .expect("certificate has a direct signature")
            .packet
    }

    /// Returns the verified self-issued key revocations.
    pub fn revocations(&self) -> impl Iterator<Item = &SignaturePacket> {
        self.revocations.iter().map(|signature| &signature.packet)
    }

    /// Checks the primary key for revocation at a Unix timestamp.
    pub fn is_revoked_at(&self, at: u32) -> bool {
        self.revocations
            .iter()
            .any(|signature| signature.revokes_at(at))
    }

    /// Finds the primary signing key if it is current and explicitly allowed to sign.
    pub fn signing_key_at(&self, at: u32) -> Option<&PgpPublicKey> {
        self.current_primary(at)?
            .allows(0x02)
            .then_some(&self.primary_key)
    }

    /// Selects the newest current, unrevoked X25519 subkey for the requested purpose.
    ///
    /// A subkey must have the corresponding authenticated Key Flag. The
    /// caller establishes the trust of the certificate and its identity claims.
    pub fn encryption_key_at(
        &self,
        at: u32,
        purpose: PgpEncryptionPurpose,
    ) -> Option<&PgpPublicKey> {
        self.current_primary(at)?;
        self.subkeys
            .iter()
            .filter_map(|subkey| {
                let created = subkey.key.creation_time();
                let signature = current(&subkey.signatures, created, at)?;
                if signature.allows(purpose as u8) && !subkey.is_revoked_at(at) {
                    Some(((created, signature.created()), &subkey.key))
                } else {
                    None
                }
            })
            .max_by_key(|(age, _)| *age)
            .map(|(_, key)| key)
    }

    fn current_primary(&self, at: u32) -> Option<&KeySignature> {
        if self.is_revoked_at(at) {
            return None;
        }
        current(
            &self.direct_signatures,
            self.primary_key.creation_time(),
            at,
        )
    }

    pub fn user_ids(&self) -> &[PgpCertifiedUserId] {
        &self.user_ids
    }

    pub fn subkeys(&self) -> &[PgpCertifiedSubkey] {
        &self.subkeys
    }
}

/// Requested use of an encryption subkey.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PgpEncryptionPurpose {
    Communications = 0x04,
    Storage = 0x08,
}

/// An RFC 9580 reason for revoking a primary key or subkey.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PgpKeyRevocationReason {
    Unspecified = 0,
    Superseded = 1,
    Compromised = 2,
    Retired = 3,
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
    signatures: Vec<KeySignature>,
    revocations: Vec<KeySignature>,
}

impl PgpCertifiedSubkey {
    pub fn key(&self) -> &PgpPublicKey {
        &self.key
    }

    /// Returns the newest verified binding signature.
    pub fn signature(&self) -> &SignaturePacket {
        &latest(&self.signatures)
            .expect("certified subkey has a binding signature")
            .packet
    }

    /// Returns the verified primary-key-issued subkey revocations.
    pub fn revocations(&self) -> impl Iterator<Item = &SignaturePacket> {
        self.revocations.iter().map(|signature| &signature.packet)
    }

    /// Checks this subkey's revocations at a Unix timestamp.
    pub fn is_revoked_at(&self, at: u32) -> bool {
        self.revocations
            .iter()
            .any(|signature| signature.revokes_at(at))
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

    /// Appends a self-issued revocation of the primary key.
    fn revoke_primary(
        &self,
        _certificate: &mut PgpCertificate,
        _primary: &PgpKeyPair,
        _reason: PgpKeyRevocationReason,
        _creation_time: u32,
    ) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Appends a primary-key-issued revocation of the indexed subkey.
    fn revoke_subkey(
        &self,
        _certificate: &mut PgpCertificate,
        _primary: &PgpKeyPair,
        _subkey_index: usize,
        _reason: PgpKeyRevocationReason,
        _creation_time: u32,
    ) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Verifies and applies a standalone v6 primary-key revocation certificate.
    fn apply_primary_revocation(
        &self,
        _certificate: &mut PgpCertificate,
        _bytes: &[u8],
        _config: &DecodingConfig,
    ) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Writes a transferable public key in binary packet format.
    fn encode_to(&self, certificate: &PgpCertificate, output: &mut dyn Write) -> io::Result<()>;

    /// Reads exactly one certificate and verifies its self-signatures and bindings.
    ///
    /// The built-in provider supports a v6 Ed25519 primary key with Direct Key
    /// signatures, one self-signature per UTF-8 identity, and X25519 subkeys.
    /// Key and subkey revocations must be signed by the primary key.
    /// The caller establishes identity trust.
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
