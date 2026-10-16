use crate::{EcError, EcKeyGenerationParams, EcPrivateKey, EcPublicKey};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_ec_core_v2::Curve;

pub struct EcKeyPairGenerator<'a, C: Curve> {
    params: Option<EcKeyGenerationParams<'a, C>>,
}

impl<C: Curve> KeyPairGenerator for EcKeyPairGenerator<'_, C> {
    type PublicKey = EcPublicKey<C>;
    type PrivateKey = EcPrivateKey<C>;
    type Error = EcError;

    fn generate_key_pair(&mut self) -> Result<(EcPublicKey<C>, EcPrivateKey<C>), EcError> {
        todo!()
    }
}

impl<'a, C: Curve> KeyPairGeneratorInit<EcKeyGenerationParams<'a, C>>
    for EcKeyPairGenerator<'a, C>
{
    type Error = EcError;

    fn init(&mut self, _params: EcKeyGenerationParams<'a, C>) -> Result<(), EcError> {
        todo!()
    }
}
