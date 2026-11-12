use crate::params::AnyPrivateKey;

// What an agreement's init takes, as plain data: this party's private key and, for the agreements
// that take them, its ephemeral private key and user keying material. Nothing here checks its
// contents; init does
#[derive(Clone, Debug)]
pub struct AnyAgreementParams {
    key: AnyPrivateKey,
    // ECMQV needs it, as Bouncy Castle's MqvPrivateParameters hold it, and the others refuse it
    ephemeral: Option<AnyPrivateKey>,
    // ECVKO needs it, the agreements with a KDF may take it, and the others refuse it
    ukm: Option<Vec<u8>>,
}

impl AnyAgreementParams {
    pub fn new(key: AnyPrivateKey) -> Self {
        Self {
            key,
            ephemeral: None,
            ukm: None,
        }
    }

    pub fn with_ephemeral(mut self, ephemeral: AnyPrivateKey) -> Self {
        self.ephemeral = Some(ephemeral);
        self
    }

    pub fn with_ukm(mut self, ukm: Vec<u8>) -> Self {
        self.ukm = Some(ukm);
        self
    }

    pub fn key(&self) -> &AnyPrivateKey {
        &self.key
    }

    pub fn ephemeral(&self) -> Option<&AnyPrivateKey> {
        self.ephemeral.as_ref()
    }

    pub fn ukm(&self) -> Option<&[u8]> {
        self.ukm.as_deref()
    }
}

// The private key alone, as every agreement but ECMQV and ECVKO takes
impl From<AnyPrivateKey> for AnyAgreementParams {
    fn from(key: AnyPrivateKey) -> Self {
        Self::new(key)
    }
}
