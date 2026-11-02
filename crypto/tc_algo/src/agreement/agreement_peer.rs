use crate::params::AnyPublicKey;

// What calculate takes from the other party, as plain data: its public key and, for ECMQV, its
// ephemeral public key too, Bouncy Castle's MqvPublicParameters. Nothing here checks its
// contents; calculate does
#[derive(Clone, Debug)]
pub struct AgreementPeer {
    key: AnyPublicKey,
    // ECMQV needs it, and the others refuse it
    ephemeral: Option<AnyPublicKey>,
}

impl AgreementPeer {
    pub fn new(key: AnyPublicKey) -> Self {
        Self {
            key,
            ephemeral: None,
        }
    }

    pub fn with_ephemeral(mut self, ephemeral: AnyPublicKey) -> Self {
        self.ephemeral = Some(ephemeral);
        self
    }

    pub fn key(&self) -> &AnyPublicKey {
        &self.key
    }

    pub fn ephemeral(&self) -> Option<&AnyPublicKey> {
        self.ephemeral.as_ref()
    }
}

// The public key alone, as every agreement but ECMQV takes
impl From<AnyPublicKey> for AgreementPeer {
    fn from(key: AnyPublicKey) -> Self {
        Self::new(key)
    }
}
