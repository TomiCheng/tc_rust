use rand::CryptoRng;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;

use super::{GeneratorEntry, KeyGenParams};
use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

/// 依名稱取得的產生器；有預設值的 `init` 可以不呼叫，沒呼叫時用預設值。
pub struct Generator {
    entry: &'static GeneratorEntry,
    params: Option<KeyGenParams>,
    rng: Box<dyn CryptoRng + Send>,
}

impl Generator {
    pub(super) fn new(entry: &'static GeneratorEntry, params: Option<KeyGenParams>) -> Self {
        Self {
            entry,
            params,
            rng: Box::new(UnwrapErr(SysRng)),
        }
    }

    /// 改用自訂的亂數來源，例如 DRBG 或測試用的固定種子；沒呼叫時用作業系統的亂數。
    pub fn with_rng(&mut self, rng: impl CryptoRng + Send + 'static) -> &mut Self {
        self.rng = Box::new(rng);
        self
    }

    /// 用 `params` 取代目前的參數。收到不屬於這個演算法的 variant，或數值不是它接受的，
    /// 回傳 `InvalidKeyGenParams`，目前的參數不變。
    pub fn init(&mut self, params: &KeyGenParams) -> Result<(), SecurityError> {
        self.entry.check_params(params)?;
        self.params = Some(*params);
        Ok(())
    }

    /// 產生一把對稱金鑰，同 BC 的 `GenerateKeyParameter`。金鑰對的產生器（例如 RSA）回傳 `WrongGenerator`；
    /// 沒有預設參數又還沒 `init` 時回傳 `MissingKeyGenParams`。
    pub fn generate_key(&mut self) -> Result<AnyParams, SecurityError> {
        let params = self.params.ok_or(SecurityError::MissingKeyGenParams)?;
        self.entry.generate_key(&params, &mut *self.rng)
    }

    /// 產生一組金鑰對（公鑰, 私鑰），同 BC 的 `GenerateKeyPair`。對稱金鑰的產生器回傳 `WrongGenerator`；
    /// 沒有預設參數又還沒 `init` 時是 `MissingKeyGenParams`；底層的產生器失敗時，錯誤包成 `AnyError`。
    pub fn generate_key_pair(&mut self) -> Result<(AnyParams, AnyParams), AnyError> {
        let params = self
            .params
            .ok_or_else(|| AnyError::new(SecurityError::MissingKeyGenParams))?;
        self.entry.generate_key_pair(&params, &mut *self.rng)
    }
}
