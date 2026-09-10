//! 變動時間：只能用於公開值。模運算委派 `BigInt`，輸出採模數寬度。
//! 會洩漏數值與指數，不提供有號 Montgomery 或 CT 模運算。
use super::ops::public_result;
use crate::{ModAdd, ModInverse, ModMul, ModPow, ModSub, PaddedBigInt};

/// 變動時間：只能用於公開值。輸出寬度為模數寬度，不可逆時回 `None`。
impl ModInverse for PaddedBigInt {
    type Output = Self;
    fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        self.to_big_int()
            .mod_inverse(&modulus.to_big_int())
            .map(|v| public_result(v, modulus.len()))
    }
}
/// 變動時間：只能用於公開值與公開指數。輸出寬度為模數寬度。
/// 此 trait 委派 BigInt，會洩漏指數，不可用於秘密指數。
impl ModPow for PaddedBigInt {
    type Output = Self;
    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        public_result(
            self.to_big_int()
                .mod_pow(&exponent.to_big_int(), &modulus.to_big_int()),
            modulus.len(),
        )
    }
}
macro_rules! modular_operator {
    ($trait:ident, $method:ident) => {
        /// 變動時間：只能用於公開值。輸出寬度為模數寬度；模數為零時 panic。
        /// 本型別不提供 CT 模運算。
        impl $trait for PaddedBigInt {
            type Output = Self;
            fn $method(&self, rhs: &Self, modulus: &Self) -> Self {
                public_result(
                    self.to_big_int()
                        .$method(&rhs.to_big_int(), &modulus.to_big_int()),
                    modulus.len(),
                )
            }
        }
    };
}
modular_operator!(ModAdd, mod_add);
modular_operator!(ModSub, mod_sub);
modular_operator!(ModMul, mod_mul);
