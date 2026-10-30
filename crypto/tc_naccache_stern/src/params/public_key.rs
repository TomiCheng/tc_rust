use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;

/// BC 的公開 `NaccacheSternKeyParameters`：g、n 與 σ 的位元數（`LowerSigmaBound`）。只是
/// 容器，建構時不檢查，引擎的 `init` 才檢查。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NaccacheSternPublicKey {
    g: PaddedBigUint,
    n: PaddedBigUint,
    lower_sigma_bound: u32,
}

impl NaccacheSternPublicKey {
    /// 包起 g、n 與 σ 的位元數，不檢查。常數時間。
    pub fn new(g: PaddedBigUint, n: PaddedBigUint, lower_sigma_bound: u32) -> Self {
        Self {
            g,
            n,
            lower_sigma_bound,
        }
    }

    /// g。常數時間。
    pub fn g(&self) -> &PaddedBigUint {
        &self.g
    }

    /// 模數 n。常數時間。
    pub fn n(&self) -> &PaddedBigUint {
        &self.n
    }

    /// σ 的位元數，明文要小於 σ。常數時間。
    pub fn lower_sigma_bound(&self) -> u32 {
        self.lower_sigma_bound
    }
}

impl AsymmetricKeyParams for NaccacheSternPublicKey {
    /// 公鑰。常數時間。
    fn is_private_key(&self) -> bool {
        false
    }
}
