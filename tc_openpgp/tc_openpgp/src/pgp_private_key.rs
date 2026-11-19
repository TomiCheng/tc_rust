use tc_algo::Params;
use tc_openpgp_packet::PublicKeyAlgorithmTag;

/// An in-memory OpenPGP private key.
pub struct PgpPrivateKey {
    algorithm: PublicKeyAlgorithmTag,
    key: Box<dyn Params>,
}

impl PgpPrivateKey {
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
