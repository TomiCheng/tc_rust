use tc_algo::Params;
use tc_openpgp_packet::PublicKeyAlgorithmTag;

/// An in-memory OpenPGP public key.
pub struct PgpPublicKey {
    algorithm: PublicKeyAlgorithmTag,
    key: Box<dyn Params>,
}

impl PgpPublicKey {
    pub fn new(algorithm: PublicKeyAlgorithmTag, key: Box<dyn Params>) -> Self {
        Self { algorithm, key }
    }

    pub fn algorithm(&self) -> PublicKeyAlgorithmTag {
        self.algorithm
    }

    pub fn key(&self) -> &dyn Params {
        self.key.as_ref()
    }
}
