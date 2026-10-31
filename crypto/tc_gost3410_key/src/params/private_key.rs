use crate::{Gost3410Error, Gost3410Parameters};
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::{BigUint, PaddedBigUint};
use tc_zeroize::Zeroize;

/// BC 的 `Gost3410PrivateKeyParameters`：私鑰 x 與它的參數；drop 時清除 x。只是容器，
/// [`validate`](Self::validate) 做 BC 建構子的檢查。
///
/// 沒有 `Debug` 與 `PartialEq`，以免印出或以變動時間比較 x。
#[derive(Clone)]
pub struct Gost3410PrivateKey {
    x: PaddedBigUint,
    params: Gost3410Parameters,
}

impl Gost3410PrivateKey {
    /// 包起 x 與參數，不檢查。常數時間。
    pub fn new(x: PaddedBigUint, params: Gost3410Parameters) -> Self {
        Self { x, params }
    }

    /// 私鑰 x。常數時間。
    pub fn x(&self) -> &PaddedBigUint {
        &self.x
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &Gost3410Parameters {
        &self.params
    }

    /// 參數合格，且 x 在 `[1, q − 1]`、至多 256 位元，同 BC 的建構子。對 x 是常數時間：只
    /// 透露是否通過；參數只依公開值檢查。
    pub fn validate(&self) -> Result<(), Gost3410Error> {
        self.params.validate()?;
        let mut limit = BigUint::from(0u8);
        limit.set_bit(256, true);
        let limit = PaddedBigUint::from(limit);
        if self.x < PaddedBigUint::from(1u8) || &self.x >= self.params.q() || self.x >= limit {
            return Err(Gost3410Error::InvalidPrivateKey);
        }
        Ok(())
    }
}

impl AsymmetricKeyParams for Gost3410PrivateKey {
    /// 私鑰。常數時間。
    fn is_private_key(&self) -> bool {
        true
    }
}

impl Drop for Gost3410PrivateKey {
    /// 清除 x。常數時間。
    fn drop(&mut self) {
        self.x.zeroize();
    }
}
