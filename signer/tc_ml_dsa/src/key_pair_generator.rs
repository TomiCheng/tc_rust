use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_zeroize::Zeroize;

use crate::{MlDsaError, MlDsaParameters, MlDsaPrivateKey, MlDsaPublicKey};

/// BC 的 `MLDsaKeyGenerationParameters`：參數組與亂數來源。
pub struct MlDsaKeyGenerationParams<'a> {
    params: MlDsaParameters,
    rng: &'a mut dyn CryptoRng,
}

impl<'a> MlDsaKeyGenerationParams<'a> {
    /// 參數組與亂數來源。常數時間。
    pub fn new(params: MlDsaParameters, rng: &'a mut dyn CryptoRng) -> Self {
        Self { params, rng }
    }

    /// 參數組。常數時間。
    pub fn params(&self) -> MlDsaParameters {
        self.params
    }
}

/// BC 的 `MLDsaKeyPairGenerator`：抽 32 位元組的 seed，以 [`MlDsaPrivateKey::from_seed`] 算出
/// 金鑰對。
#[derive(Default)]
pub struct MlDsaKeyPairGenerator<'a> {
    params: Option<MlDsaKeyGenerationParams<'a>>,
}

impl MlDsaKeyPairGenerator<'_> {
    /// 尚未 `init` 的產生器。常數時間。
    pub fn new() -> Self {
        Self { params: None }
    }
}

impl<'a> KeyPairGeneratorInit<MlDsaKeyGenerationParams<'a>> for MlDsaKeyPairGenerator<'a> {
    type Error = MlDsaError;

    /// 收下參數組與亂數來源。常數時間。
    fn init(&mut self, params: MlDsaKeyGenerationParams<'a>) -> Result<(), MlDsaError> {
        self.params = Some(params);
        Ok(())
    }
}

impl KeyPairGenerator for MlDsaKeyPairGenerator<'_> {
    type PublicKey = MlDsaPublicKey;
    type PrivateKey = MlDsaPrivateKey;
    type Error = MlDsaError;

    /// BC 的 `GenerateKeyPair`：seed 取自亂數來源，用畢清除。
    fn generate_key_pair(&mut self) -> Result<(MlDsaPublicKey, MlDsaPrivateKey), MlDsaError> {
        let params = self.params.as_mut().ok_or(MlDsaError::NotInitialized)?;
        let mut seed = [0u8; 32];
        params.rng.fill_bytes(&mut seed);
        let private_key = MlDsaPrivateKey::from_seed(params.params, seed);
        seed.zeroize();
        Ok((private_key.public_key(), private_key))
    }
}
