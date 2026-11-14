use crate::{
    ElGamalError, ElGamalKeyGenerationParams, ElGamalParameters, ElGamalPrivateKey,
    ElGamalPublicKey,
};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_dh_key::{DhKeyGenerationParams, DhKeyPairGenerator};

/// BC 的 `ElGamalKeyPairGenerator`：把參數轉成沒有 q、m = 0 的 DH 參數，交給
/// `tc_dh_key` 的 [`DhKeyPairGenerator`] 產生 x 與 y = g^x mod p。
pub struct ElGamalKeyPairGenerator<R> {
    inner: DhKeyPairGenerator<R>,
    params: Option<ElGamalParameters>,
}

impl<R> ElGamalKeyPairGenerator<R> {
    /// 從 `rng` 取亂數、尚未 `init` 的產生器。常數時間。
    pub fn new(rng: R) -> Self {
        Self {
            inner: DhKeyPairGenerator::new(rng),
            params: None,
        }
    }
}

impl<R> KeyPairGeneratorInit<ElGamalKeyGenerationParams> for ElGamalKeyPairGenerator<R> {
    type Error = ElGamalError;

    /// 以 DH 的檢查驗證參數。變動時間：參數是公開值。
    fn init(&mut self, params: &ElGamalKeyGenerationParams) -> Result<(), ElGamalError> {
        self.params = None;
        let dh = DhKeyGenerationParams::new(params.params.to_dh());
        self.inner.init(&dh)?;
        self.params = Some(params.params.clone());
        Ok(())
    }
}

impl<R: CryptoRng> KeyPairGenerator for ElGamalKeyPairGenerator<R> {
    type PublicKey = ElGamalPublicKey;
    type PrivateKey = ElGamalPrivateKey;
    type Error = ElGamalError;

    /// x 在 `[2, p - 2]` 或為 l 位元，y = g^x mod p，同 DH。對 x 是常數時間，只有被丟棄的
    /// 候選值多少會反映在時間上。
    fn generate_key_pair(&mut self) -> Result<(ElGamalPublicKey, ElGamalPrivateKey), ElGamalError> {
        let params = self.params.as_ref().ok_or(ElGamalError::NotInitialized)?;
        let (public_key, private_key) = self.inner.generate_key_pair()?;
        Ok((
            ElGamalPublicKey::new(public_key.y().clone(), params.clone()),
            ElGamalPrivateKey::new(private_key.x().clone(), params.clone()),
        ))
    }
}
