use crate::math::{naf_weight, random_in_range};
use crate::{DsaError, DsaKeyGenerationParams, DsaPrivateKey, DsaPublicKey};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

/// BC 的 `DsaKeyPairGenerator`：x 在 `[1, q − 1]` 且 NAF 權重至少是 q 的位元數的四分之一，
/// y = g^x mod p。`init` 檢查參數並為 p 建好 Montgomery 參數。
pub struct DsaKeyPairGenerator<'a> {
    state: Option<(DsaKeyGenerationParams<'a>, PaddedMontyParams)>,
}

impl DsaKeyPairGenerator<'_> {
    /// 尚未 `init` 的產生器。常數時間。
    pub fn new() -> Self {
        Self { state: None }
    }
}

impl Default for DsaKeyPairGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> KeyPairGeneratorInit<DsaKeyGenerationParams<'a>> for DsaKeyPairGenerator<'a> {
    type Error = DsaError;

    /// 以 [`DsaParameters::validate`](crate::DsaParameters::validate) 檢查參數，並為 p 建好
    /// Montgomery 參數。變動時間：參數是公開值。
    fn init(&mut self, params: DsaKeyGenerationParams<'a>) -> Result<(), DsaError> {
        self.state = None;
        params.params.validate()?;
        let p = Odd::new(params.params.p().clone()).ok_or(DsaError::InvalidModulus)?;
        self.state = Some((params, PaddedMontyParams::new(p)));
        Ok(())
    }
}

impl KeyPairGenerator for DsaKeyPairGenerator<'_> {
    type PublicKey = DsaPublicKey;
    type PrivateKey = DsaPrivateKey;
    type Error = DsaError;

    /// BC 的 `GenerateKeyPair`：照 BC 讀取亂數（q 的位元數，依大端序），丟棄不合格的
    /// 候選值；y = g^x mod p。對 x 是常數時間：比較、NAF 權重與取冪都不依 x 分支，丟棄的
    /// 候選值會清除；只有重抽的次數反映在時間上，與最後的 x 無關。
    fn generate_key_pair(&mut self) -> Result<(DsaPublicKey, DsaPrivateKey), DsaError> {
        let (params, monty) = self.state.as_mut().ok_or(DsaError::NotInitialized)?;
        let q = params.params.q();
        let one = PaddedBigUint::from(1u8);
        let high = q - 1u32;
        let min_weight = q.bits() >> 2;
        let x = loop {
            let mut x = random_in_range(params.rng, &one, &high);
            if naf_weight(x.as_limbs()) >= min_weight {
                break x;
            }
            x.zeroize();
        };
        let power = Zeroizing::new(PaddedMontyForm::new(params.params.g(), monty).pow(&x));
        let y = power.retrieve();
        Ok((
            DsaPublicKey::new(y, params.params.clone()),
            DsaPrivateKey::new(x, params.params.clone()),
        ))
    }
}
