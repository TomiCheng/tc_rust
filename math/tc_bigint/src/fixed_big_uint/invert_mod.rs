//! Modular inverse support for [`FixedBigUint`].

#[cfg(feature = "alloc")]
use alloc::vec;

#[cfg(feature = "alloc")]
use crate::{ArrayEncoding, Odd, modular::FixedMontyParams};
use crate::{FixedBigUint, modular};

impl<const N: usize> FixedBigUint<N> {
    /// 以固定排程計算奇數模數下的乘法反元素。
    ///
    /// 模數與儲存寬度是公開資訊；輸入值會先以固定排程約簡。回傳值只會揭露
    /// 輸入是否可逆，呼叫端若處理秘密值，應確保協定本身保證它可逆。
    #[cfg(feature = "alloc")]
    pub fn mod_odd_inverse_ct(&self, modulus: &Odd<Self>) -> Option<Self> {
        let params = FixedMontyParams::new(*modulus);
        let reduced = modular::FixedMontyForm::new_ct(self, params).retrieve();
        let words = modulus.as_ref().u32_length_unsigned();
        let mut modulus_words = vec![0_u32; words];
        let mut value_words = vec![0_u32; words];
        let mut output = vec![0_u32; words];
        modulus
            .as_ref()
            .write_unsigned_le_u32(&mut modulus_words)
            .expect("寬度由公開模數決定");
        reduced
            .write_unsigned_le_u32(&mut value_words)
            .expect("寬度由公開模數決定");

        modular::mod_odd_inverse(&modulus_words, &value_words, &mut output)
            .then(|| Self::from_le_u32(&output).expect("反元素必定符合原本的固定寬度"))
    }

    /// 以變動時間計算奇數模數下的乘法反元素。
    ///
    /// 只適合公開輸入；相較固定排程版本，此入口適合簽章驗證等不處理秘密值的
    /// 路徑。
    #[cfg(feature = "alloc")]
    pub fn mod_odd_inverse_vartime(&self, modulus: &Odd<Self>) -> Option<Self> {
        let params = FixedMontyParams::new(*modulus);
        let reduced = modular::FixedMontyForm::new(self, params).retrieve();
        let modulus_words = ArrayEncoding::to_unsigned_le_u32(modulus.as_ref());
        let mut value_words = ArrayEncoding::to_unsigned_le_u32(&reduced);
        value_words.resize(modulus_words.len(), 0);
        let mut output = vec![0; modulus_words.len()];

        modular::mod_odd_inverse_var(&modulus_words, &value_words, &mut output)
            .then(|| Self::from_le_u32(&output).expect("反元素必定符合原本的固定寬度"))
    }

    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        modular::fixed_mod_inverse(self.limbs.as_limbs(), modulus.limbs.as_limbs()).map(|limbs| {
            Self {
                limbs: crate::LimbArray::new(limbs),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use crate::Odd;
    use crate::Word;

    type U128 = FixedBigUint<{ 128 / Word::BITS as usize }>;

    #[test]
    fn inverse_matches_known_values() {
        let three = U128::from(3_u8);
        assert_eq!(three.mod_inverse(&U128::from(7_u8)), Some(U128::from(5_u8)));
        assert_eq!(
            three.mod_inverse(&U128::from(10_u8)),
            Some(U128::from(7_u8))
        );

        let max = U128::max_value();
        assert_eq!(
            U128::from(2_u8).mod_inverse(&max),
            Some(U128::from(1_u8) << 127)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn constant_time_odd_inverse_reduces_and_inverts() {
        let modulus = Odd::new(U128::from(101_u8)).unwrap();

        assert_eq!(
            U128::from(108_u8).mod_odd_inverse_ct(&modulus),
            Some(U128::from(29_u8))
        );
        assert_eq!(U128::zero().mod_odd_inverse_ct(&modulus), None);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn constant_time_odd_inverse_uses_public_modulus_width_for_every_value() {
        let modulus = Odd::new(U128::max_value()).unwrap();
        let low_value = U128::from(2_u8);
        let high_value = U128::from(1_u8) << 127;

        assert_eq!(low_value.mod_odd_inverse_ct(&modulus), Some(high_value));
        assert_eq!(high_value.mod_odd_inverse_ct(&modulus), Some(low_value));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn variable_time_odd_inverse_reduces_and_inverts() {
        let modulus = Odd::new(U128::from(101_u8)).unwrap();

        assert_eq!(
            U128::from(108_u8).mod_odd_inverse_vartime(&modulus),
            Some(U128::from(29_u8))
        );
        assert_eq!(U128::zero().mod_odd_inverse_vartime(&modulus), None);
    }

    #[test]
    #[should_panic(expected = "modulus must be non-zero")]
    fn inverse_rejects_zero_modulus() {
        let _ = U128::from(1_u8).mod_inverse(&U128::zero());
    }
}
