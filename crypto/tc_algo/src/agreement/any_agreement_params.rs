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
        todo!()
    }

    pub fn with_ukm(self, ukm: Vec<u8>) -> Self {
        todo!()
    }

    pub fn key(&self) -> &AnyPrivateKey {
        todo!()
    }

    pub fn ukm(&self) -> Option<&[u8]> {
        todo!()
    }
}
