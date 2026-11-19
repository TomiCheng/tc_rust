use crate::{PgpPrivateKey, PgpPublicKey};

/// The two keys generated together for an OpenPGP algorithm.
pub struct PgpKeyPair {
    public: PgpPublicKey,
    private: PgpPrivateKey,
}

impl PgpKeyPair {
    pub fn new(public: PgpPublicKey, private: PgpPrivateKey) -> Self {
        Self { public, private }
    }

    pub fn public(&self) -> &PgpPublicKey {
        &self.public
    }

    pub fn private(&self) -> &PgpPrivateKey {
        &self.private
    }

    pub fn into_parts(self) -> (PgpPublicKey, PgpPrivateKey) {
        (self.public, self.private)
    }
}
