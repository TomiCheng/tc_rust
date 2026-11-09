use alloc::vec::Vec;

use tc_asym_cipher::AsymmetricKeyParams;
use tc_zeroize::Zeroize;

use crate::engine::{self, KeyMaterial};
use crate::{MlDsaError, MlDsaParameters};

/// BC 的 `MLDsaPublicKeyParameters`：ρ ‖ t1 與參數組。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaPublicKey {
    params: MlDsaParameters,
    rho: [u8; 32],
    t1: Vec<u8>,
}

impl MlDsaPublicKey {
    /// BC 的 `FromEncoding`：長度要對。常數時間。
    pub fn from_encoding(params: MlDsaParameters, encoding: &[u8]) -> Result<Self, MlDsaError> {
        if encoding.len() != params.public_key_length() {
            return Err(MlDsaError::InvalidKeyLength);
        }
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&encoding[..32]);
        Ok(Self {
            params,
            rho,
            t1: encoding[32..].to_vec(),
        })
    }

    /// 參數組。常數時間。
    pub fn params(&self) -> MlDsaParameters {
        self.params
    }

    /// BC 的 `GetEncoded`：ρ ‖ t1。常數時間。
    pub fn encoding(&self) -> Vec<u8> {
        [&self.rho[..], &self.t1].concat()
    }

    pub(crate) fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    pub(crate) fn t1(&self) -> &[u8] {
        &self.t1
    }

    /// tr = H(ρ ‖ t1)。常數時間。
    pub(crate) fn hash(&self) -> [u8; 64] {
        engine::public_key_hash(&self.rho, &self.t1)
    }
}

impl AsymmetricKeyParams for MlDsaPublicKey {
    /// 公鑰。常數時間。
    fn is_private_key(&self) -> bool {
        false
    }
}

/// BC 的 `MLDsaPrivateKeyParameters`：ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0、算出的 t1，以及產生它的 32
/// 位元組 seed（若有）；drop 時清除 seed、K 與秘密向量。
#[derive(Clone)]
pub struct MlDsaPrivateKey {
    params: MlDsaParameters,
    seed: Option<[u8; 32]>,
    material: KeyMaterial,
}

impl MlDsaPrivateKey {
    /// BC 的 `FromSeed`（ML-DSA.KeyGen_internal）。對 seed 是常數時間，除了取樣的拒絕次數。
    pub fn from_seed(params: MlDsaParameters, seed: [u8; 32]) -> Self {
        let material = engine::generate_key_pair(&params, &seed);
        Self {
            params,
            seed: Some(seed),
            material,
        }
    }

    /// BC 的 `FromEncoding`：長度要對，t1 由編碼重算；沒有 seed。對秘密是常數時間。
    pub fn from_encoding(params: MlDsaParameters, encoding: &[u8]) -> Result<Self, MlDsaError> {
        if encoding.len() != params.private_key_length() {
            return Err(MlDsaError::InvalidKeyLength);
        }
        let eta = params.eta_packed_bytes();
        let (rho_bytes, rest) = encoding.split_at(32);
        let (k_bytes, rest) = rest.split_at(32);
        let (tr_bytes, rest) = rest.split_at(64);
        let (s1, rest) = rest.split_at(params.l() * eta);
        let (s2, t0) = rest.split_at(params.k() * eta);
        let mut rho = [0u8; 32];
        rho.copy_from_slice(rho_bytes);
        let mut k = [0u8; 32];
        k.copy_from_slice(k_bytes);
        let mut tr = [0u8; 64];
        tr.copy_from_slice(tr_bytes);
        let t1 = engine::derive_t1(&params, &rho, s1, s2, t0);
        Ok(Self {
            params,
            seed: None,
            material: KeyMaterial {
                rho,
                k,
                tr,
                s1: s1.to_vec(),
                s2: s2.to_vec(),
                t0: t0.to_vec(),
                t1,
            },
        })
    }

    /// 參數組。常數時間。
    pub fn params(&self) -> MlDsaParameters {
        self.params
    }

    /// 產生金鑰的 seed，以 `from_encoding` 建立時沒有。常數時間。
    pub fn seed(&self) -> Option<&[u8; 32]> {
        self.seed.as_ref()
    }

    /// BC 的 `GetEncoded`：ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0。常數時間。
    pub fn encoding(&self) -> Vec<u8> {
        let m = &self.material;
        [&m.rho[..], &m.k, &m.tr, &m.s1, &m.s2, &m.t0].concat()
    }

    /// BC 的 `GetPublicKey`。常數時間。
    pub fn public_key(&self) -> MlDsaPublicKey {
        MlDsaPublicKey {
            params: self.params,
            rho: self.material.rho,
            t1: self.material.t1.clone(),
        }
    }

    pub(crate) fn material(&self) -> &KeyMaterial {
        &self.material
    }
}

impl AsymmetricKeyParams for MlDsaPrivateKey {
    /// 私鑰。常數時間。
    fn is_private_key(&self) -> bool {
        true
    }
}

impl Drop for MlDsaPrivateKey {
    /// 清除 seed、K、s1、s2 與 t0。常數時間。
    fn drop(&mut self) {
        self.seed.zeroize();
        self.material.k.zeroize();
        self.material.s1.zeroize();
        self.material.s2.zeroize();
        self.material.t0.zeroize();
    }
}

impl Clone for KeyMaterial {
    fn clone(&self) -> Self {
        Self {
            rho: self.rho,
            k: self.k,
            tr: self.tr,
            s1: self.s1.clone(),
            s2: self.s2.clone(),
            t0: self.t0.clone(),
            t1: self.t1.clone(),
        }
    }
}
