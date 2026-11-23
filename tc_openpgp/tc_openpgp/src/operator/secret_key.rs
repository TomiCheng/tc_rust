use std::io::{self, Write};

use tc_openpgp_packet::{ArmorKind, AsciiArmor, DecodingConfig};

use crate::{PgpCertificate, PgpKeyPair};

#[cfg(feature = "secret-key")]
mod v6;

/// Limits applied before deriving keys from imported Argon2id parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretKeyLimits {
    pub max_memory_kib: u32,
    pub max_passes: u8,
    /// Maximum number of protected key packets, including the primary key.
    pub max_keys: usize,
}

impl Default for SecretKeyLimits {
    fn default() -> Self {
        Self {
            max_memory_kib: 64 * 1024,
            max_passes: 3,
            max_keys: 16,
        }
    }
}

/// A verified public certificate with its unlocked primary key and subkeys.
pub struct PgpUnlockedSecretKey {
    certificate: PgpCertificate,
    primary: PgpKeyPair,
    subkeys: Vec<PgpKeyPair>,
}

impl PgpUnlockedSecretKey {
    pub fn certificate(&self) -> &PgpCertificate {
        &self.certificate
    }

    pub fn primary(&self) -> &PgpKeyPair {
        &self.primary
    }

    pub fn subkeys(&self) -> &[PgpKeyPair] {
        &self.subkeys
    }
}

/// Imports and exports passphrase-protected transferable secret keys.
pub trait PgpSecretKeyProvider: Send + Sync {
    /// Writes the protected key bundle. Supply subkeys in certificate order.
    fn export(
        &self,
        certificate: &PgpCertificate,
        primary: &PgpKeyPair,
        subkeys: &[&PgpKeyPair],
        passphrase: &[u8],
        output: &mut dyn Write,
    ) -> io::Result<()>;

    /// Authenticates the protected key material and checks its public counterpart.
    fn import(
        &self,
        input: &[u8],
        passphrase: &[u8],
        config: &DecodingConfig,
        limits: &SecretKeyLimits,
    ) -> io::Result<PgpUnlockedSecretKey>;

    fn export_armored(
        &self,
        certificate: &PgpCertificate,
        primary: &PgpKeyPair,
        subkeys: &[&PgpKeyPair],
        passphrase: &[u8],
    ) -> io::Result<String> {
        let mut binary = Vec::new();
        self.export(certificate, primary, subkeys, passphrase, &mut binary)?;
        AsciiArmor::encode(ArmorKind::PrivateKey, &binary)
    }

    fn import_armored(
        &self,
        text: &str,
        passphrase: &[u8],
        config: &DecodingConfig,
        limits: &SecretKeyLimits,
    ) -> io::Result<PgpUnlockedSecretKey> {
        self.import(
            &AsciiArmor::decode(ArmorKind::PrivateKey, text)?,
            passphrase,
            config,
            limits,
        )
    }
}

pub(crate) struct EmptySecretKeyProvider;

impl PgpSecretKeyProvider for EmptySecretKeyProvider {
    fn export(
        &self,
        _: &PgpCertificate,
        _: &PgpKeyPair,
        _: &[&PgpKeyPair],
        _: &[u8],
        _: &mut dyn Write,
    ) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn import(
        &self,
        _: &[u8],
        _: &[u8],
        _: &DecodingConfig,
        _: &SecretKeyLimits,
    ) -> io::Result<PgpUnlockedSecretKey> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
