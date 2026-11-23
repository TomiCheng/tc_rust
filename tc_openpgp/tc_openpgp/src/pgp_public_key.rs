use std::time::{SystemTime, UNIX_EPOCH};

use tc_algo::Params;
use tc_openpgp_packet::{PublicKeyAlgorithmTag, PublicKeyVersion};

/// An in-memory OpenPGP public key and its packet metadata.
pub struct PgpPublicKey {
    algorithm: PublicKeyAlgorithmTag,
    key: Box<dyn Params>,
    version: PublicKeyVersion,
    creation_time: u32,
}

impl PgpPublicKey {
    /// Creates a key with the current time. RSA defaults to v4, and other keys default to v6.
    pub fn new(algorithm: PublicKeyAlgorithmTag, key: Box<dyn Params>) -> Self {
        let version = match algorithm {
            PublicKeyAlgorithmTag::RsaGeneral
            | PublicKeyAlgorithmTag::RsaEncrypt
            | PublicKeyAlgorithmTag::RsaSign => PublicKeyVersion::V4,
            _ => PublicKeyVersion::V6,
        };
        let creation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
            });
        Self::new_with_metadata(algorithm, key, version, creation_time)
    }

    pub fn new_with_metadata(
        algorithm: PublicKeyAlgorithmTag,
        key: Box<dyn Params>,
        version: PublicKeyVersion,
        creation_time: u32,
    ) -> Self {
        Self {
            algorithm,
            key,
            version,
            creation_time,
        }
    }

    pub fn algorithm(&self) -> PublicKeyAlgorithmTag {
        self.algorithm
    }

    pub fn key(&self) -> &dyn Params {
        self.key.as_ref()
    }

    pub fn version(&self) -> PublicKeyVersion {
        self.version
    }

    /// Seconds since the Unix epoch as encoded in the Public Key packet.
    pub fn creation_time(&self) -> u32 {
        self.creation_time
    }
}
