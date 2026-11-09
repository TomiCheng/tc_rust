use alloc::vec::Vec;

use tc_asym_cipher::AsymmetricKeyParams;
use tc_zeroize::Zeroize;

use crate::hash::Hasher;
use crate::tree::Tree;
use crate::{SlhDsaError, SlhDsaParameters};

fn array(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

/// BC 的 `SlhDsaPublicKeyParameters`：PK.seed ‖ PK.root 與參數組。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhDsaPublicKey {
    params: SlhDsaParameters,
    seed: [u8; 32],
    root: [u8; 32],
}

impl SlhDsaPublicKey {
    /// BC 的 `FromEncoding`：長度要對。常數時間。
    pub fn from_encoding(params: SlhDsaParameters, encoding: &[u8]) -> Result<Self, SlhDsaError> {
        if encoding.len() != params.public_key_length() {
            return Err(SlhDsaError::InvalidKeyLength);
        }
        let n = params.n();
        Ok(Self {
            params,
            seed: array(&encoding[..n]),
            root: array(&encoding[n..]),
        })
    }

    /// 參數組。常數時間。
    pub fn params(&self) -> SlhDsaParameters {
        self.params
    }

    /// BC 的 `GetEncoded`：PK.seed ‖ PK.root。常數時間。
    pub fn encoding(&self) -> Vec<u8> {
        let n = self.params.n();
        [&self.seed[..n], &self.root[..n]].concat()
    }

    pub(crate) fn seed(&self) -> &[u8] {
        &self.seed[..self.params.n()]
    }

    pub(crate) fn root(&self) -> &[u8] {
        &self.root[..self.params.n()]
    }
}

impl AsymmetricKeyParams for SlhDsaPublicKey {
    /// 公鑰。常數時間。
    fn is_private_key(&self) -> bool {
        false
    }
}

/// BC 的 `SlhDsaPrivateKeyParameters`：SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root；drop 時清除
/// SK.seed 與 SK.prf。
#[derive(Clone)]
pub struct SlhDsaPrivateKey {
    params: SlhDsaParameters,
    sk_seed: [u8; 32],
    sk_prf: [u8; 32],
    public: SlhDsaPublicKey,
}

impl SlhDsaPrivateKey {
    /// FIPS 205 的 slh_keygen_internal：由三個 n 位元組的種子算出 PK.root。種子長度不對時是
    /// `InvalidKeyLength`。對種子是常數時間。
    pub fn from_seeds(
        params: SlhDsaParameters,
        sk_seed: &[u8],
        sk_prf: &[u8],
        pk_seed: &[u8],
    ) -> Result<Self, SlhDsaError> {
        let n = params.n();
        if sk_seed.len() != n || sk_prf.len() != n || pk_seed.len() != n {
            return Err(SlhDsaError::InvalidKeyLength);
        }
        let hasher = Hasher::new(params, pk_seed);
        let mut root = [0u8; 32];
        Tree::new(params, &hasher, sk_seed).ht_root(&mut root[..n]);
        Ok(Self {
            params,
            sk_seed: array(sk_seed),
            sk_prf: array(sk_prf),
            public: SlhDsaPublicKey {
                params,
                seed: array(pk_seed),
                root,
            },
        })
    }

    /// BC 的 `FromEncoding`：長度要對；PK.root 照編碼收下，不重算。常數時間。
    pub fn from_encoding(params: SlhDsaParameters, encoding: &[u8]) -> Result<Self, SlhDsaError> {
        if encoding.len() != params.private_key_length() {
            return Err(SlhDsaError::InvalidKeyLength);
        }
        let n = params.n();
        Ok(Self {
            params,
            sk_seed: array(&encoding[..n]),
            sk_prf: array(&encoding[n..2 * n]),
            public: SlhDsaPublicKey::from_encoding(params, &encoding[2 * n..])?,
        })
    }

    /// 參數組。常數時間。
    pub fn params(&self) -> SlhDsaParameters {
        self.params
    }

    /// BC 的 `GetEncoded`：SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root。常數時間。
    pub fn encoding(&self) -> Vec<u8> {
        let n = self.params.n();
        [
            &self.sk_seed[..n],
            &self.sk_prf[..n],
            &self.public.encoding(),
        ]
        .concat()
    }

    /// BC 的 `GetPublicKey`。常數時間。
    pub fn public_key(&self) -> SlhDsaPublicKey {
        self.public.clone()
    }

    pub(crate) fn sk_seed(&self) -> &[u8] {
        &self.sk_seed[..self.params.n()]
    }

    pub(crate) fn sk_prf(&self) -> &[u8] {
        &self.sk_prf[..self.params.n()]
    }

    pub(crate) fn public(&self) -> &SlhDsaPublicKey {
        &self.public
    }
}

impl AsymmetricKeyParams for SlhDsaPrivateKey {
    /// 私鑰。常數時間。
    fn is_private_key(&self) -> bool {
        true
    }
}

impl Drop for SlhDsaPrivateKey {
    /// 清除 SK.seed 與 SK.prf。常數時間。
    fn drop(&mut self) {
        self.sk_seed.zeroize();
        self.sk_prf.zeroize();
    }
}
