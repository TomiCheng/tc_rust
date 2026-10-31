use crate::{DsaError, DsaParameters};
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;
use tc_modular::{ModPow, NonZero};

/// BC 的 `DsaPublicKeyParameters`：公鑰 y = g^x mod p 與它的參數。只是容器，
/// [`validate`](Self::validate) 做 BC 建構子的檢查。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsaPublicKey {
    y: PaddedBigUint,
    params: DsaParameters,
}

impl DsaPublicKey {
    /// 包起 y 與參數，不檢查。常數時間。
    pub fn new(y: PaddedBigUint, params: DsaParameters) -> Self {
        Self { y, params }
    }

    /// 公鑰 y。常數時間。
    pub fn y(&self) -> &PaddedBigUint {
        &self.y
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &DsaParameters {
        &self.params
    }

    /// BC 的 `Validate`：參數合格，y 在 `[2, p − 2]` 且 y^q ≡ 1 (mod p)。變動時間：只能用於
    /// 公開值。
    pub fn validate(&self) -> Result<(), DsaError> {
        self.params.validate()?;
        let p = self.params.p();
        if self.y < PaddedBigUint::from(2u8) || self.y > p - 2u32 {
            return Err(DsaError::InvalidPublicKey);
        }
        let modulus = NonZero::new(p.clone()).ok_or(DsaError::InvalidModulus)?;
        if self.y.mod_pow(self.params.q(), &modulus) != PaddedBigUint::from(1u8) {
            return Err(DsaError::InvalidPublicKey);
        }
        Ok(())
    }
}

impl AsymmetricKeyParams for DsaPublicKey {
    /// 公鑰。常數時間。
    fn is_private_key(&self) -> bool {
        false
    }
}
