use crate::{MlKemError, MlKemParameters, MlKemPrivateKey, MlKemPublicKey};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_zeroize::Zeroize;

/// BC 的 `MLKemKeyGenerationParameters`：參數組與亂數來源。
pub struct MlKemKeyGenerationParams<'a> {
    params: MlKemParameters,
    rng: &'a mut dyn CryptoRng,
}

impl<'a> MlKemKeyGenerationParams<'a> {
    /// 參數組與亂數來源。常數時間。
    pub fn new(params: MlKemParameters, rng: &'a mut dyn CryptoRng) -> Self {
        Self { params, rng }
    }

    /// 參數組。常數時間。
    pub fn params(&self) -> MlKemParameters {
        self.params
    }
}

/// BC 的 `MLKemKeyPairGenerator`：抽 64 位元組的 seed，以
/// [`MlKemPrivateKey::from_seed`] 算出金鑰對。
pub struct MlKemKeyPairGenerator<'a> {
    params: Option<MlKemKeyGenerationParams<'a>>,
}

impl MlKemKeyPairGenerator<'_> {
    /// 尚未 `init` 的產生器。常數時間。
    pub fn new() -> Self {
        Self { params: None }
    }
}

impl Default for MlKemKeyPairGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> KeyPairGeneratorInit<MlKemKeyGenerationParams<'a>> for MlKemKeyPairGenerator<'a> {
    type Error = MlKemError;

    /// 收下參數組與亂數來源；三組參數都是常數，沒有要檢查的。常數時間。
    fn init(&mut self, params: MlKemKeyGenerationParams<'a>) -> Result<(), MlKemError> {
        self.params = Some(params);
        Ok(())
    }
}

impl KeyPairGenerator for MlKemKeyPairGenerator<'_> {
    type PublicKey = MlKemPublicKey;
    type PrivateKey = MlKemPrivateKey;
    type Error = MlKemError;

    /// BC 的 `GenerateKeyPair`：seed = d ‖ z 取自亂數來源，抽到的位元組用畢清除。對 seed 是
    /// 常數時間。
    fn generate_key_pair(&mut self) -> Result<(MlKemPublicKey, MlKemPrivateKey), MlKemError> {
        let params = self.params.as_mut().ok_or(MlKemError::NotInitialized)?;
        let mut seed = [0u8; 64];
        params.rng.fill_bytes(&mut seed);
        let private_key = MlKemPrivateKey::from_seed(params.params, seed);
        seed.zeroize();
        Ok((private_key.public_key(), private_key))
    }
}
