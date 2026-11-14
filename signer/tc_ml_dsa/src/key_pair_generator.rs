use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_zeroize::Zeroize;

use crate::{MlDsaError, MlDsaParameters, MlDsaPrivateKey, MlDsaPublicKey};

/// BC 的 `MLDsaKeyGenerationParameters`，不含亂數來源：亂數來源在產生器建構時給。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlDsaKeyGenerationParams {
    params: MlDsaParameters,
}

impl MlDsaKeyGenerationParams {
    /// 參數組。常數時間。
    pub fn new(params: MlDsaParameters) -> Self {
        Self { params }
    }

    /// 參數組。常數時間。
    pub fn params(&self) -> MlDsaParameters {
        self.params
    }
}

/// BC 的 `MLDsaKeyPairGenerator`：抽 32 位元組的 seed，以 [`MlDsaPrivateKey::from_seed`] 算出
/// 金鑰對。
#[derive(Default)]
pub struct MlDsaKeyPairGenerator<R> {
    rng: R,
    params: Option<MlDsaKeyGenerationParams>,
}

impl<R> MlDsaKeyPairGenerator<R> {
    /// 從 `rng` 取亂數、尚未 `init` 的產生器。常數時間。
    pub fn new(rng: R) -> Self {
        Self { rng, params: None }
    }
}

impl<R> KeyPairGeneratorInit<MlDsaKeyGenerationParams> for MlDsaKeyPairGenerator<R> {
    type Error = MlDsaError;

    /// 收下參數組。常數時間。
    fn init(&mut self, params: &MlDsaKeyGenerationParams) -> Result<(), MlDsaError> {
        self.params = Some(*params);
        Ok(())
    }
}

impl<R: CryptoRng> KeyPairGenerator for MlDsaKeyPairGenerator<R> {
    type PublicKey = MlDsaPublicKey;
    type PrivateKey = MlDsaPrivateKey;
    type Error = MlDsaError;

    /// BC 的 `GenerateKeyPair`：seed 取自亂數來源，用畢清除。
    fn generate_key_pair(&mut self) -> Result<(MlDsaPublicKey, MlDsaPrivateKey), MlDsaError> {
        let params = self.params.as_ref().ok_or(MlDsaError::NotInitialized)?;
        let mut seed = [0u8; 32];
        self.rng.fill_bytes(&mut seed);
        let private_key = MlDsaPrivateKey::from_seed(params.params, seed);
        seed.zeroize();
        Ok((private_key.public_key(), private_key))
    }
}
