use crate::{Gost3410Error, Gost3410Parameters};
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;

/// BC 的 `Gost3410PublicKeyParameters`：公鑰 y = a^x mod p 與它的參數。只是容器，
/// [`validate`](Self::validate) 做 BC 建構子的檢查。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gost3410PublicKey {
    y: PaddedBigUint,
    params: Gost3410Parameters,
}

impl Gost3410PublicKey {
    /// 包起 y 與參數，不檢查。常數時間。
    pub fn new(y: PaddedBigUint, params: Gost3410Parameters) -> Self {
        Self { y, params }
    }

    /// 公鑰 y。常數時間。
    pub fn y(&self) -> &PaddedBigUint {
        &self.y
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &Gost3410Parameters {
        &self.params
    }

    /// 參數合格，且 y 在 `[1, p − 1]`，同 BC 的建構子。變動時間：只能用於公開值。
    pub fn validate(&self) -> Result<(), Gost3410Error> {
        self.params.validate()?;
        if self.y < PaddedBigUint::from(1u8) || &self.y >= self.params.p() {
            return Err(Gost3410Error::InvalidPublicKey);
        }
        Ok(())
    }
}

impl AsymmetricKeyParams for Gost3410PublicKey {
    /// 公鑰。常數時間。
    fn is_private_key(&self) -> bool {
        false
    }
}
