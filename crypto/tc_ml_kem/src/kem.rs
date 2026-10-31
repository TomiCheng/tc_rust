use crate::{MlKemError, MlKemParameters, MlKemPrivateKey, MlKemPublicKey, engine};
use rand_core::CryptoRng;
use tc_kem::{KemDecapsulator, KemEncapsulator, KemInit};
use tc_zeroize::Zeroizing;

/// BC 的 `MLKemEncapsulator`：以封裝金鑰產生密文與 32 位元組的共享秘密；m 由 `R` 抽取。
pub struct MlKemEncapsulator<R> {
    params: MlKemParameters,
    rng: R,
    key: Option<MlKemPublicKey>,
}

impl<R> MlKemEncapsulator<R> {
    /// 給 `params` 的金鑰用、尚未 `init` 的封裝方。常數時間。
    pub fn new(params: MlKemParameters, rng: R) -> Self {
        Self {
            params,
            rng,
            key: None,
        }
    }
}

impl<R> KemInit<MlKemPublicKey> for MlKemEncapsulator<R> {
    type Error = MlKemError;

    /// 金鑰的參數組要相同，並通過 [`MlKemPublicKey::validate`]；失敗時維持未初始化。變動
    /// 時間：只能用於公開值。
    fn init(&mut self, key: &MlKemPublicKey) -> Result<(), MlKemError> {
        self.key = None;
        if key.params() != self.params {
            return Err(MlKemError::ParameterMismatch);
        }
        key.validate()?;
        self.key = Some(key.clone());
        Ok(())
    }
}

impl<R: CryptoRng> KemEncapsulator for MlKemEncapsulator<R> {
    type Error = MlKemError;

    /// 密文的位元組數。常數時間。
    fn encapsulation_length(&self) -> usize {
        self.params.encapsulation_length()
    }

    /// 32。常數時間。
    fn secret_length(&self) -> usize {
        self.params.secret_length()
    }

    /// BC 的 `Encapsulate`（FIPS 203 的 ML-KEM.Encaps）：抽 32 位元組的 m，寫出密文與共享
    /// 秘密；緩衝區長度要恰好相符。對 m 與共享秘密是常數時間。
    fn encapsulate(
        &mut self,
        encapsulation: &mut [u8],
        secret: &mut [u8],
    ) -> Result<(), MlKemError> {
        let key = self.key.as_ref().ok_or(MlKemError::NotInitialized)?;
        if encapsulation.len() != self.params.encapsulation_length() {
            return Err(MlKemError::InvalidEncapsulationLength);
        }
        if secret.len() != self.params.secret_length() {
            return Err(MlKemError::InvalidSecretLength);
        }
        let mut message = Zeroizing::new([0u8; 32]);
        self.rng.fill_bytes(&mut message[..]);
        engine::encapsulate(
            &self.params,
            key.encoding(),
            &message,
            encapsulation,
            secret,
        );
        Ok(())
    }
}

/// BC 的 `MLKemDecapsulator`：以解封裝金鑰從密文取回共享秘密，失敗時給隱式拒絕的值。
pub struct MlKemDecapsulator {
    params: MlKemParameters,
    key: Option<MlKemPrivateKey>,
}

impl MlKemDecapsulator {
    /// 給 `params` 的金鑰用、尚未 `init` 的解封裝方。常數時間。
    pub fn new(params: MlKemParameters) -> Self {
        Self { params, key: None }
    }
}

impl KemInit<MlKemPrivateKey> for MlKemDecapsulator {
    type Error = MlKemError;

    /// 金鑰的參數組要相同，並通過 [`MlKemPrivateKey::validate`]；保存複本，drop 時清除。
    /// 失敗時維持未初始化。常數時間：雜湊檢查只透露是否通過。
    fn init(&mut self, key: &MlKemPrivateKey) -> Result<(), MlKemError> {
        self.key = None;
        if key.params() != self.params {
            return Err(MlKemError::ParameterMismatch);
        }
        key.validate()?;
        self.key = Some(key.clone());
        Ok(())
    }
}

impl KemDecapsulator for MlKemDecapsulator {
    type Error = MlKemError;

    /// 密文的位元組數。常數時間。
    fn encapsulation_length(&self) -> usize {
        self.params.encapsulation_length()
    }

    /// 32。常數時間。
    fn secret_length(&self) -> usize {
        self.params.secret_length()
    }

    /// BC 的 `Decapsulate`（FIPS 203 的 ML-KEM.Decaps）：緩衝區長度要恰好相符；密文被竄改
    /// 時給隱式拒絕的值，不回傳錯誤。常數時間：密文是否被竄改不由時間透露。
    fn decapsulate(&mut self, encapsulation: &[u8], secret: &mut [u8]) -> Result<(), MlKemError> {
        let key = self.key.as_ref().ok_or(MlKemError::NotInitialized)?;
        if encapsulation.len() != self.params.encapsulation_length() {
            return Err(MlKemError::InvalidEncapsulationLength);
        }
        if secret.len() != self.params.secret_length() {
            return Err(MlKemError::InvalidSecretLength);
        }
        engine::decapsulate(&self.params, key.encoding(), encapsulation, secret);
        Ok(())
    }
}
