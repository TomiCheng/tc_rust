//! 變動時間：只能用於公開值。模運算委派 `BigUint`，輸出採模數寬度。
//! 秘密值與秘密指數請直接用 [`crate::modular::PaddedMontyForm`] 的 CT 入口。
use super::ops::public_result;
use crate::{ModAdd, ModInverse, ModMul, ModPow, ModSub, PaddedBigUint};

/// 變動時間：只能用於公開值。輸出寬度為模數寬度，不可逆時回 `None`。
impl ModInverse for PaddedBigUint {
    type Output = Self;
    fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        self.to_big_uint()
            .mod_inverse(&modulus.to_big_uint())
            .map(|v| public_result(v, modulus.len()))
    }
}
/// 變動時間：只能用於公開值與公開指數。輸出寬度為模數寬度。
/// 秘密指數請用 [`crate::modular::PaddedMontyForm::pow_ct`]，此 trait 會洩漏指數。
impl ModPow for PaddedBigUint {
    type Output = Self;
    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        public_result(
            self.to_big_uint()
                .mod_pow(&exponent.to_big_uint(), &modulus.to_big_uint()),
            modulus.len(),
        )
    }
}
macro_rules! modular_operator {
    ($trait:ident, $method:ident) => {
        /// 變動時間：只能用於公開值。輸出寬度為模數寬度；模數為零時 panic。
        /// 秘密值請使用 [`crate::modular::PaddedMontyForm`]。
        impl $trait for PaddedBigUint {
            type Output = Self;
            fn $method(&self, rhs: &Self, modulus: &Self) -> Self {
                public_result(
                    self.to_big_uint()
                        .$method(&rhs.to_big_uint(), &modulus.to_big_uint()),
                    modulus.len(),
                )
            }
        }
    };
}
modular_operator!(ModAdd, mod_add);
modular_operator!(ModSub, mod_sub);
modular_operator!(ModMul, mod_mul);
