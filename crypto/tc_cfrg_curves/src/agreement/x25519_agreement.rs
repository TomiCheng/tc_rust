use crate::rfc7748::x25519;
use crate::{CfrgError, X25519PrivateKey, X25519PublicKey};
use tc_agreement::{Agreement, AgreementInit};
use tc_zeroize::Zeroize;

pub struct X25519Agreement {
    private_key: Option<X25519PrivateKey>,
}

impl X25519Agreement {
    pub fn new() -> Self {
        Self { private_key: None }
    }
}

impl Default for X25519Agreement {
    fn default() -> Self {
        Self::new()
    }
}

impl AgreementInit<X25519PrivateKey> for X25519Agreement {
    type Error = CfrgError;

    fn init(&mut self, params: &X25519PrivateKey) -> Result<(), CfrgError> {
        self.private_key = Some(params.clone());
        Ok(())
    }
}

impl Agreement for X25519Agreement {
    type PublicKey = X25519PublicKey;
    type Error = CfrgError;

    fn agreement_size(&self) -> usize {
        X25519PublicKey::SIZE
    }

    fn calculate_agreement(
        &self,
        public_key: &X25519PublicKey,
        output: &mut [u8],
    ) -> Result<(), CfrgError> {
        let private_key = self.private_key.as_ref().ok_or(CfrgError::NotInitialized)?;
        let output = output
            .get_mut(..X25519PublicKey::SIZE)
            .ok_or(CfrgError::OutputTooShort)?;
        let mut secret = x25519::calculate_agreement(private_key.k(), public_key.u())
            .ok_or(CfrgError::AgreementFailed)?;
        output.copy_from_slice(&secret);
        secret.zeroize();
        Ok(())
    }
}
