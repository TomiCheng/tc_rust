use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_zeroize::Zeroize;

use crate::{SlhDsaError, SlhDsaParameters, SlhDsaPrivateKey, SlhDsaPublicKey};

/// BC 的 `SlhDsaKeyGenerationParameters`，不含亂數來源：亂數來源在產生器建構時給。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlhDsaKeyGenerationParams {
    params: SlhDsaParameters,
}

impl SlhDsaKeyGenerationParams {
    /// 參數組。常數時間。
    pub fn new(params: SlhDsaParameters) -> Self {
        Self { params }
    }

    /// 參數組。常數時間。
    pub fn params(&self) -> SlhDsaParameters {
        self.params
    }
}

/// BC 的 `SlhDsaKeyPairGenerator`：抽 SK.seed、SK.prf 與 PK.seed，以
/// [`SlhDsaPrivateKey::from_seeds`] 算出金鑰對。
#[derive(Default)]
pub struct SlhDsaKeyPairGenerator<R> {
    rng: R,
    params: Option<SlhDsaKeyGenerationParams>,
}

impl<R> SlhDsaKeyPairGenerator<R> {
    /// 從 `rng` 取亂數、尚未 `init` 的產生器。常數時間。
    pub fn new(rng: R) -> Self {
        Self { rng, params: None }
    }
}

impl<R> KeyPairGeneratorInit<SlhDsaKeyGenerationParams> for SlhDsaKeyPairGenerator<R> {
    type Error = SlhDsaError;

    /// 收下參數組。常數時間。
    fn init(&mut self, params: &SlhDsaKeyGenerationParams) -> Result<(), SlhDsaError> {
        self.params = Some(*params);
        Ok(())
    }
}

impl<R: CryptoRng> KeyPairGenerator for SlhDsaKeyPairGenerator<R> {
    type PublicKey = SlhDsaPublicKey;
    type PrivateKey = SlhDsaPrivateKey;
    type Error = SlhDsaError;

    /// BC 的 `GenerateKeyPair`：三個種子依序取自亂數來源，用畢清除。
    fn generate_key_pair(&mut self) -> Result<(SlhDsaPublicKey, SlhDsaPrivateKey), SlhDsaError> {
        let params = self.params.as_ref().ok_or(SlhDsaError::NotInitialized)?;
        let n = params.params.n();
        let mut seeds = [0u8; 96];
        self.rng.fill_bytes(&mut seeds[..3 * n]);
        let key = SlhDsaPrivateKey::from_seeds(
            params.params,
            &seeds[..n],
            &seeds[n..2 * n],
            &seeds[2 * n..3 * n],
        );
        seeds.zeroize();
        let key = key?;
        Ok((key.public_key(), key))
    }
}
