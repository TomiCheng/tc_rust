use crate::math::legendre;
use crate::{DhError, DhParameters};
use tc_bigint::{BigUint, PaddedBigUint};
use tc_modular::{ModPow, NonZero};

// BC `Properties.DHMaxSize` 的預設值：p 最多的位元數。
const MAX_MODULUS_BITS: u32 = 16384;

/// BC 的 `DHPublicKeyParameters`：公開值 y = g^x mod p 與它的參數。
///
/// 只是容器，建構時不檢查；[`validate`](Self::validate) 做 BC 建構子的檢查，由使用公鑰的
/// 運算呼叫。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhPublicKey {
    y: PaddedBigUint,
    params: DhParameters,
}

impl DhPublicKey {
    /// 包起 y 與參數，不檢查。常數時間。
    pub fn new(y: PaddedBigUint, params: DhParameters) -> Self {
        Self { y, params }
    }

    /// 公開值 y。常數時間。
    pub fn y(&self) -> &PaddedBigUint {
        &self.y
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &DhParameters {
        &self.params
    }

    /// BC `DHPublicKeyParameters.Validate`：p 不超過 16384 位元，y 在 `[2, p - 2]`；有 q
    /// 時 y 要在 q 階子群裡，p = 2q + 1 時以 Legendre 符號判斷，否則看 y^q mod p 是否為 1。
    /// 參數本身由 [`DhParameters::validate`] 檢查。變動時間：y 與參數都是公開值。
    pub fn validate(&self) -> Result<(), DhError> {
        let p = BigUint::from(self.params.p().clone());
        if p.bits() > MAX_MODULUS_BITS {
            return Err(DhError::ModulusTooLarge);
        }
        let y = BigUint::from(self.y.clone());
        let two = BigUint::from(2u8);
        if p <= two || y < two || y > &p - 2u32 {
            return Err(DhError::InvalidPublicValue);
        }
        let Some(q) = self.params.q() else {
            return Ok(());
        };
        let q = BigUint::from(q.clone());
        let in_subgroup = if p.bit(0) && p.bits() - 1 == q.bits() && (&p >> 1) == q {
            legendre(&y, &p) == 1
        } else {
            let modulus = NonZero::new(p).expect("p is above 2");
            y.mod_pow(&q, &modulus) == BigUint::from(1u8)
        };
        if !in_subgroup {
            return Err(DhError::PublicValueOutsideSubgroup);
        }
        Ok(())
    }
}
