use crate::params::AnyPrivateKey;

// What an agreement's init takes, as plain data: this party's private key and, for the agreements
// that take it, user keying material. Nothing here checks its contents; init does
#[derive(Clone, Debug)]
pub struct AnyAgreementParams {
    key: AnyPrivateKey,
    // ECVKO needs it, the agreements with a KDF may take it, and the others refuse it
    ukm: Option<Vec<u8>>,
}

impl AnyAgreementParams {
    pub fn new(key: AnyPrivateKey) -> Self {
        Self { key, ukm: None }
    }

    pub fn with_ukm(mut self, ukm: Vec<u8>) -> Self {
        self.ukm = Some(ukm);
        self
    }

    pub fn key(&self) -> &AnyPrivateKey {
        &self.key
    }

    pub fn ukm(&self) -> Option<&[u8]> {
        self.ukm.as_deref()
    }
}
