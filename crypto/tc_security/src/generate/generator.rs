use rand::CryptoRng;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;

use super::{GeneratorEntry, KeyGenParams};
use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

/// 依名稱取得的產生器；`init` 可以不呼叫，沒呼叫時用預設值。
pub struct Generator {
    // 哪個演算法：決定 init 收哪些參數、產生對稱金鑰還是金鑰對
    entry: &'static GeneratorEntry,
    // 目前的參數；一開始是這一列的預設參數，init 會換掉
    params: KeyGenParams,
    // 產生金鑰的亂數來源；一開始是作業系統的亂數，with_rng 會換掉
    rng: Box<dyn CryptoRng + Send>,
}

impl Generator {
    pub(super) fn new(entry: &'static GeneratorEntry, params: KeyGenParams) -> Self {
        Self {
            entry,
            params,
            // 作業系統的亂數取不到時 panic；這種情況下也沒有安全的金鑰可產生
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
        self.params = self.entry.check_params(params)?;
        Ok(())
    }

    /// 產生一把對稱金鑰，同 BC 的 `GenerateKeyParameter`：長度取 `strength` bits 進位到整數個 byte，
    /// 全部取自亂數來源。金鑰對的產生器（例如 RSA）回傳 `WrongGenerator`。
    pub fn generate_key(&mut self) -> Result<AnyParams, SecurityError> {
        match self.params {
            KeyGenParams::Basic { strength } => Ok(AnyParams::new(self.random_bytes(strength))),
            #[cfg(feature = "rc2")]
            KeyGenParams::Rc2 {
                strength,
                effective_key_bits,
            } => Ok(AnyParams::rc2(
                self.random_bytes(strength),
                effective_key_bits,
            )),
            #[cfg(feature = "rsa")]
            KeyGenParams::Rsa { .. } => Err(SecurityError::WrongGenerator),
        }
    }

    fn random_bytes(&mut self, strength: usize) -> Vec<u8> {
        let mut bytes = vec![0; strength.div_ceil(8)];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }

    /// 產生一組金鑰對（公鑰, 私鑰），同 BC 的 `GenerateKeyPair`；兩個都是 `AnyParams`，例如 `AnyParams::Rsa`。
    /// 對稱金鑰的產生器回傳 `WrongGenerator`；底層的產生器失敗時（例如長度或指數不合用），錯誤包成 `AnyError`。
    pub fn generate_key_pair(&mut self) -> Result<(AnyParams, AnyParams), AnyError> {
        match self.params {
            #[cfg(feature = "rsa")]
            KeyGenParams::Rsa {
                public_exponent,
                strength,
                certainty,
            } => {
                use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
                use tc_rsa::{RsaKeyGenerationParamsRef, RsaKeyGenerator};

                let strength = u32::try_from(strength)
                    .map_err(|_| AnyError::new(SecurityError::InvalidKeyGenParams))?;
                let params = RsaKeyGenerationParamsRef::new(&mut *self.rng)
                    .with_public_exponent(public_exponent)
                    .with_strength(strength)
                    .with_certainty(certainty);
                let mut generator = RsaKeyGenerator::new();
                generator.init(params).map_err(AnyError::new)?;
                let (public, private) = generator.generate_key_pair().map_err(AnyError::new)?;
                Ok((AnyParams::rsa(public), AnyParams::rsa(private)))
            }
            KeyGenParams::Basic { .. } => Err(AnyError::new(SecurityError::WrongGenerator)),
            #[cfg(feature = "rc2")]
            KeyGenParams::Rc2 { .. } => Err(AnyError::new(SecurityError::WrongGenerator)),
        }
    }
}
