use crate::{CfrgError, X448PrivateKey, X448PublicKey};
use tc_agreement::{Agreement, AgreementInit};

pub struct X448Agreement {
    private_key: Option<X448PrivateKey>,
}

impl X448Agreement {
    pub fn new() -> Self {
        Self { private_key: None }
    }
}

impl Default for X448Agreement {
    fn default() -> Self {
        Self::new()
    }
}

impl AgreementInit<X448PrivateKey> for X448Agreement {
    type Error = CfrgError;

    fn init(&mut self, params: &X448PrivateKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl Agreement for X448Agreement {
    type PublicKey = X448PublicKey;
    type Error = CfrgError;

    fn agreement_size(&self) -> usize {
        X448PublicKey::SIZE
    }

    fn calculate_agreement(
        &self,
        public_key: &X448PublicKey,
        output: &mut [u8],
    ) -> Result<(), CfrgError> {
        todo!()
    }
}
