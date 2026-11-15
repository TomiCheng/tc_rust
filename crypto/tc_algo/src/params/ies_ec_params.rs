use core::any::Any;

use tc_bigint::PaddedBigUint;
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};

use crate::Params;

// The params of the ECIES row, as IesDhParams for IES: this side's private key and the other side's
// public key on one curve, with what Bouncy Castle's IesParameters holds. The curve is the type C of
// the keys, such as &'static FpCtCurve<'static> or &'static SecPCtCurve<SecP256R1FieldElement>
pub struct IesEcParams<C: Curve<Scalar = PaddedBigUint>> {
    private_key: EcPrivateKey<C>,
    public_key: EcPublicKey<C>,
    derivation_v: Vec<u8>,
    encoding_v: Vec<u8>,
    mac_key_bits: usize,
}

impl<C: Curve<Scalar = PaddedBigUint>> IesEcParams<C> {
    pub fn new(
        private_key: EcPrivateKey<C>,
        public_key: EcPublicKey<C>,
        derivation_v: Vec<u8>,
        encoding_v: Vec<u8>,
        mac_key_bits: usize,
    ) -> Self {
        Self {
            private_key,
            public_key,
            derivation_v,
            encoding_v,
            mac_key_bits,
        }
    }

    pub fn private_key(&self) -> &EcPrivateKey<C> {
        &self.private_key
    }

    pub fn public_key(&self) -> &EcPublicKey<C> {
        &self.public_key
    }

    pub fn derivation_v(&self) -> &[u8] {
        &self.derivation_v
    }

    pub fn encoding_v(&self) -> &[u8] {
        &self.encoding_v
    }

    pub fn mac_key_bits(&self) -> usize {
        self.mac_key_bits
    }
}

impl<C> Params for IesEcParams<C>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
    EcPrivateKey<C>: Send + Sync,
    EcPublicKey<C>: Send + Sync,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
}
