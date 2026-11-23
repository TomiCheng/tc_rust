use std::io::{self, Write};

use tc_openpgp_packet::{ArmorKind, AsciiArmor, DecodingConfig};

use crate::{PgpCertificate, PgpKeyPair};

#[cfg(feature = "legacy-encryption")]
mod v4_rsa;
#[cfg(feature = "secret-key")]
mod v6;

/// Limits applied when importing protected OpenPGP secret keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretKeyLimits {
    /// Maximum Argon2id memory in KiB.
    pub max_memory_kib: u32,
    /// Maximum Argon2id passes.
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

/// A v4 RSA primary key and its unlocked RSA subkeys in packet order.
///
/// These key pairs expose the secret-key material. Certificate signatures and
/// identity trust are outside the scope of a v4 secret-key import.
pub struct PgpRsaSecretKeys {
    primary: PgpKeyPair,
    subkeys: Vec<PgpKeyPair>,
}

impl PgpRsaSecretKeys {
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

    /// Imports an AES-CFB-protected v4 RSA key bundle with iterated-and-salted S2K.
    ///
    /// The built-in provider enables this operation with the legacy-encryption feature.
    fn import_v4_rsa(
        &self,
        _input: &[u8],
        _passphrase: &[u8],
        _config: &DecodingConfig,
        _limits: &SecretKeyLimits,
    ) -> io::Result<PgpRsaSecretKeys> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn import_v4_rsa_armored(
        &self,
        text: &str,
        passphrase: &[u8],
        config: &DecodingConfig,
        limits: &SecretKeyLimits,
    ) -> io::Result<PgpRsaSecretKeys> {
        self.import_v4_rsa(
            &AsciiArmor::decode(ArmorKind::PrivateKey, text)?,
            passphrase,
            config,
            limits,
        )
    }

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

#[cfg(any(feature = "secret-key", feature = "legacy-encryption"))]
pub(crate) struct DefaultSecretKeys {
    pub(crate) algo: std::sync::Arc<dyn tc_algo::Algo>,
}

#[cfg(feature = "secret-key")]
impl DefaultSecretKeys {
    fn v6(&self) -> super::certificate::V6Certificates {
        super::certificate::V6Certificates {
            signatures: super::detached_signature::Ed25519DetachedSignatures {
                algo: self.algo.clone(),
            },
        }
    }
}

#[cfg(any(feature = "secret-key", feature = "legacy-encryption"))]
impl PgpSecretKeyProvider for DefaultSecretKeys {
    fn export(
        &self,
        _certificate: &PgpCertificate,
        _primary: &PgpKeyPair,
        _subkeys: &[&PgpKeyPair],
        _passphrase: &[u8],
        _output: &mut dyn Write,
    ) -> io::Result<()> {
        #[cfg(feature = "secret-key")]
        {
            self.v6()
                .export(_certificate, _primary, _subkeys, _passphrase, _output)
        }
        #[cfg(not(feature = "secret-key"))]
        Err(io::ErrorKind::Unsupported.into())
    }

    fn import(
        &self,
        _input: &[u8],
        _passphrase: &[u8],
        _config: &DecodingConfig,
        _limits: &SecretKeyLimits,
    ) -> io::Result<PgpUnlockedSecretKey> {
        #[cfg(feature = "secret-key")]
        {
            self.v6().import(_input, _passphrase, _config, _limits)
        }
        #[cfg(not(feature = "secret-key"))]
        Err(io::ErrorKind::Unsupported.into())
    }

    #[cfg(feature = "legacy-encryption")]
    fn import_v4_rsa(
        &self,
        input: &[u8],
        passphrase: &[u8],
        config: &DecodingConfig,
        limits: &SecretKeyLimits,
    ) -> io::Result<PgpRsaSecretKeys> {
        v4_rsa::import(&*self.algo, input, passphrase, config, limits)
    }
}
