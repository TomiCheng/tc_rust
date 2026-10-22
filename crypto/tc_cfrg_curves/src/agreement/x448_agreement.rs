use crate::rfc7748::x448;
use crate::{CfrgError, X448PrivateKey, X448PublicKey};
use tc_agreement::{Agreement, AgreementInit};
use tc_zeroize::Zeroize;

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
        self.private_key = Some(params.clone());
        Ok(())
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
        let private_key = self.private_key.as_ref().ok_or(CfrgError::NotInitialized)?;
        let output = output
            .get_mut(..X448PublicKey::SIZE)
            .ok_or(CfrgError::OutputTooShort)?;
        let mut secret = x448::calculate_agreement(private_key.k(), public_key.u())
            .ok_or(CfrgError::AgreementFailed)?;
        output.copy_from_slice(&secret);
        secret.zeroize();
        Ok(())
    }
}
