use crate::NaccacheSternPublicKey;
use alloc::vec::Vec;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;
use tc_zeroize::Zeroize;

/// BC 的 `NaccacheSternPrivateKeyParameters`：公開的 g、n、σ 位元數，加上小質數表與
/// φ(n)；drop 時清除 φ(n) 與小質數的順序（順序透露哪些質數屬於 p − 1）。只是容器，
/// 建構時不檢查，引擎的 `init` 才檢查。
///
/// 沒有 `Debug` 與 `PartialEq`，以免印出或以變動時間比較 φ(n)。
#[derive(Clone)]
pub struct NaccacheSternPrivateKey {
    public: NaccacheSternPublicKey,
    small_primes: Vec<u32>,
    phi_n: PaddedBigUint,
}

impl NaccacheSternPrivateKey {
    /// 包起各值，不檢查。常數時間。
    pub fn new(
        g: PaddedBigUint,
        n: PaddedBigUint,
        lower_sigma_bound: u32,
        small_primes: Vec<u32>,
        phi_n: PaddedBigUint,
    ) -> Self {
        Self {
            public: NaccacheSternPublicKey::new(g, n, lower_sigma_bound),
            small_primes,
            phi_n,
        }
    }

    /// 對應的公鑰。常數時間。
    pub fn public_key(&self) -> &NaccacheSternPublicKey {
        &self.public
    }

    /// 小質數表，依產生時的隨機順序。常數時間。
    pub fn small_primes(&self) -> &[u32] {
        &self.small_primes
    }

    /// φ(n) = (p − 1)(q − 1)。常數時間。
    pub fn phi_n(&self) -> &PaddedBigUint {
        &self.phi_n
    }
}

impl AsymmetricKeyParams for NaccacheSternPrivateKey {
    /// 私鑰。常數時間。
    fn is_private_key(&self) -> bool {
        true
    }
}

impl Drop for NaccacheSternPrivateKey {
    /// 清除 φ(n) 與小質數的順序。常數時間。
    fn drop(&mut self) {
        self.phi_n.zeroize();
        self.small_primes.zeroize();
    }
}
