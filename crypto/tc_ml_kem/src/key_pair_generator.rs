use crate::{MlKemError, MlKemParameters, MlKemPrivateKey, MlKemPublicKey};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_zeroize::Zeroize;

/// BC 的 `MLKemKeyGenerationParameters`，不含亂數來源：亂數來源在產生器建構時給。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlKemKeyGenerationParams {
    params: MlKemParameters,
}

impl MlKemKeyGenerationParams {
    /// 參數組。常數時間。
    pub fn new(params: MlKemParameters) -> Self {
        Self { params }
    }

    /// 參數組。常數時間。
    pub fn params(&self) -> MlKemParameters {
        self.params
    }
}

/// BC 的 `MLKemKeyPairGenerator`：抽 64 位元組的 seed，以
/// [`MlKemPrivateKey::from_seed`] 算出金鑰對。
pub struct MlKemKeyPairGenerator<R> {
    rng: R,
    params: Option<MlKemKeyGenerationParams>,
}

impl<R> MlKemKeyPairGenerator<R> {
    /// 從 `rng` 取亂數、尚未 `init` 的產生器。常數時間。
    pub fn new(rng: R) -> Self {
        Self { rng, params: None }
    }
}

impl<R> KeyPairGeneratorInit<MlKemKeyGenerationParams> for MlKemKeyPairGenerator<R> {
    type Error = MlKemError;

    /// 收下參數組；三組參數都是常數，沒有要檢查的。常數時間。
    fn init(&mut self, params: &MlKemKeyGenerationParams) -> Result<(), MlKemError> {
        self.params = Some(*params);
        Ok(())
    }
}

impl<R: CryptoRng> KeyPairGenerator for MlKemKeyPairGenerator<R> {
    type PublicKey = MlKemPublicKey;
    type PrivateKey = MlKemPrivateKey;
    type Error = MlKemError;

    /// BC 的 `GenerateKeyPair`：seed = d ‖ z 取自亂數來源，抽到的位元組用畢清除。對 seed 是
    /// 常數時間。
    fn generate_key_pair(&mut self) -> Result<(MlKemPublicKey, MlKemPrivateKey), MlKemError> {
        let params = self.params.as_ref().ok_or(MlKemError::NotInitialized)?;
        let mut seed = [0u8; 64];
        self.rng.fill_bytes(&mut seed);
        let private_key = MlKemPrivateKey::from_seed(params.params, seed);
        seed.zeroize();
        Ok((private_key.public_key(), private_key))
    }
}
