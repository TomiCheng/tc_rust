use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_ec_core::{Curve, Point};
use tc_ec_key::{EcError, EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};

/// BC 的 `Dstu4145KeyPairGenerator`：同 `EcKeyPairGenerator` 產生 d，但公鑰是 Q = −d·G，
/// DSTU 4145 的慣例。
pub struct Dstu4145KeyPairGenerator<C: Curve, R> {
    inner: EcKeyPairGenerator<C, R>,
}

impl<C: Curve, R> Dstu4145KeyPairGenerator<C, R> {
    /// 從 `rng` 取亂數、尚未 `init` 的產生器。常數時間。
    pub fn new(rng: R) -> Self {
        Self {
            inner: EcKeyPairGenerator::new(rng),
        }
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, R> KeyPairGeneratorInit<EcKeyGenerationParams<C>>
    for Dstu4145KeyPairGenerator<C, R>
{
    type Error = EcError;

    /// 交給 `EcKeyPairGenerator::init`。變動時間：只依公開的 G。
    fn init(&mut self, params: &EcKeyGenerationParams<C>) -> Result<(), EcError> {
        self.inner.init(params)
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, R: CryptoRng> KeyPairGenerator
    for Dstu4145KeyPairGenerator<C, R>
{
    type PublicKey = EcPublicKey<C>;
    type PrivateKey = EcPrivateKey<C>;
    type Error = EcError;

    /// BC 的 `GenerateKeyPair`：`EcKeyPairGenerator` 的金鑰對，公鑰取負。對 d 的常數時間
    /// 程度同 `EcKeyPairGenerator`；取負只處理公開的 Q。
    fn generate_key_pair(&mut self) -> Result<(EcPublicKey<C>, EcPrivateKey<C>), EcError> {
        let (public_key, private_key) = self.inner.generate_key_pair()?;
        let q = public_key.q().negate();
        Ok((EcPublicKey::new(public_key.g().clone(), &q)?, private_key))
    }
}
