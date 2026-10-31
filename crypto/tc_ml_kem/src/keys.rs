use crate::{MlKemError, MlKemParameters, engine};
use alloc::vec;
use alloc::vec::Vec;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_zeroize::Zeroize;

/// BC 的 `MLKemPublicKeyParameters`：封裝金鑰 ek 的編碼與參數組。只是容器，
/// [`validate`](Self::validate) 做 BC `FromEncoding` 的檢查。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemPublicKey {
    params: MlKemParameters,
    encoding: Vec<u8>,
}

impl MlKemPublicKey {
    /// 包起 ek 的編碼，不檢查。常數時間。
    pub fn from_encoding(params: MlKemParameters, encoding: Vec<u8>) -> Self {
        Self { params, encoding }
    }

    /// 參數組。常數時間。
    pub fn params(&self) -> MlKemParameters {
        self.params
    }

    /// ek 的編碼。常數時間。
    pub fn encoding(&self) -> &[u8] {
        &self.encoding
    }

    /// BC 的 `FromEncoding`：長度要對，每個係數都要小於 q（FIPS 203 7.2）。變動時間：只能
    /// 用於公開值。
    pub fn validate(&self) -> Result<(), MlKemError> {
        if self.encoding.len() != self.params.public_key_length() {
            return Err(MlKemError::InvalidKeyLength);
        }
        if !engine::check_encapsulation_key(&self.params, &self.encoding) {
            return Err(MlKemError::InvalidPublicKey);
        }
        Ok(())
    }
}

impl AsymmetricKeyParams for MlKemPublicKey {
    /// 公鑰。常數時間。
    fn is_private_key(&self) -> bool {
        false
    }
}

/// BC 的 `MLKemPrivateKeyParameters`：解封裝金鑰 dk 的編碼、參數組，以及產生它的 64 位元組
/// seed（若有）；drop 時清除 seed 與 dk。BC 另有偏好的輸出格式，那屬於編碼層，這裡沒有。
#[derive(Clone)]
pub struct MlKemPrivateKey {
    params: MlKemParameters,
    seed: Option<[u8; 64]>,
    encoding: Vec<u8>,
}

impl MlKemPrivateKey {
    /// BC 的 `FromSeed`：由 seed = d ‖ z 算出 dk（FIPS 203 的 ML-KEM.KeyGen_internal）。對
    /// seed 是常數時間；Â 只依公開的 ρ。
    pub fn from_seed(params: MlKemParameters, seed: [u8; 64]) -> Self {
        let mut encoding = vec![0u8; params.private_key_length()];
        engine::generate_key_pair(&params, &seed, &mut encoding);
        Self {
            params,
            seed: Some(seed),
            encoding,
        }
    }

    /// 包起 dk 的編碼，不檢查，沒有 seed。常數時間。
    pub fn from_encoding(params: MlKemParameters, encoding: Vec<u8>) -> Self {
        Self {
            params,
            seed: None,
            encoding,
        }
    }

    /// 參數組。常數時間。
    pub fn params(&self) -> MlKemParameters {
        self.params
    }

    /// 產生 dk 的 seed，以 `from_encoding` 建立時沒有。常數時間。
    pub fn seed(&self) -> Option<&[u8; 64]> {
        self.seed.as_ref()
    }

    /// dk 的編碼。常數時間。
    pub fn encoding(&self) -> &[u8] {
        &self.encoding
    }

    /// BC 的 `GetPublicKey`：dk 裡的 ek。常數時間。
    pub fn public_key(&self) -> MlKemPublicKey {
        let start = 384 * self.params.k();
        let ek = self.encoding[start..start + self.params.public_key_length()].to_vec();
        MlKemPublicKey::from_encoding(self.params, ek)
    }

    /// BC 的 `FromEncoding`：長度要對，dk 裡的 H(ek) 要符合（FIPS 203 7.3）。常數時間：雜湊
    /// 以常數時間比較，只透露是否通過；長度是公開的。
    pub fn validate(&self) -> Result<(), MlKemError> {
        if self.encoding.len() != self.params.private_key_length() {
            return Err(MlKemError::InvalidKeyLength);
        }
        if !engine::check_decapsulation_key(&self.params, &self.encoding) {
            return Err(MlKemError::InvalidPrivateKey);
        }
        Ok(())
    }
}

impl AsymmetricKeyParams for MlKemPrivateKey {
    /// 私鑰。常數時間。
    fn is_private_key(&self) -> bool {
        true
    }
}

impl Drop for MlKemPrivateKey {
    /// 清除 seed 與 dk。常數時間。
    fn drop(&mut self) {
        if let Some(seed) = self.seed.as_mut() {
            seed.zeroize();
        }
        self.encoding.zeroize();
    }
}
