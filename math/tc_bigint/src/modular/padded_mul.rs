//! 補齊寬度的模乘與模加減，全部走固定排程。
//!
//! 這裡的每個函式最多配置一次 —— 就是它回傳的那個值。所有中間步驟都走
//! [`PaddedBigUint`] 的原地運算，因為配置與 drop 時的歸零在模冪的內圈裡
//! 會累積成主要成本。

use crate::{Choice, Limb, PaddedBigUint, WideWord, Word};

/// CT：Montgomery 乘法，排程只由模數寬度決定。
///
/// 走 CIOS，與 [`super::mul::fixed_montgomery_mul`] 同一套；最後的條件減法
/// 原地進行，不是資料相依的分支。三個運算元的寬度必須相同，
/// 且 `lhs`、`rhs` 都小於 `modulus`。
pub(super) fn montgomery_mul(
    lhs: &PaddedBigUint,
    rhs: &PaddedBigUint,
    modulus: &PaddedBigUint,
    inverse: Word,
) -> PaddedBigUint {
    lhs.assert_same_width(rhs);
    lhs.assert_same_width(modulus);
    let width = modulus.len();
    if width == 0 {
        return PaddedBigUint::zero_with_limbs(0);
    }
    debug_assert!(modulus.as_limbs()[0].to_word() & 1 == 1);

    // 這是整個函式唯一的配置：回傳值本身。內圈全部原地改它。
    let mut result = PaddedBigUint::zero_with_limbs(width);
    let mut high = 0 as Word;

    for step in 0..width {
        let right = rhs.as_limbs()[step];

        let mut carry = 0 as Word;
        for index in 0..width {
            let (low, next) = lhs.as_limbs()[index].carrying_mul_add(
                right,
                result.as_limbs()[index],
                Limb::new(carry),
            );
            result.as_limbs_mut()[index] = low;
            carry = next.to_word();
        }
        let wide = high as WideWord + carry as WideWord;
        high = wide as Word;
        let upper = (wide >> Word::BITS) as Word;

        // 約簡一個 limb：加上模數的倍數讓最低位歸零，再整體右移一個 limb。
        let multiplier = result.as_limbs()[0].to_word().wrapping_mul(inverse);
        carry = 0;
        for index in 0..width {
            let (low, next) = Limb::new(multiplier).carrying_mul_add(
                modulus.as_limbs()[index],
                result.as_limbs()[index],
                Limb::new(carry),
            );
            if index != 0 {
                result.as_limbs_mut()[index - 1] = low;
            } else {
                debug_assert_eq!(low.to_word(), 0);
            }
            carry = next.to_word();
        }
        let wide = high as WideWord + carry as WideWord;
        result.as_limbs_mut()[width - 1] = Limb::new(wide as Word);
        high = upper + (wide >> Word::BITS) as Word;
        debug_assert!(high <= 1);
    }

    // 結果落在 `[0, 2n)`，原地收進 `[0, n)`。
    result.conditional_sub_assign(modulus, Choice::from_lsb(high as u8));
    result
}

/// CT：`(lhs + rhs) mod modulus`，兩個運算元都必須已經小於模數。
pub(super) fn add_mod(
    lhs: &PaddedBigUint,
    rhs: &PaddedBigUint,
    modulus: &PaddedBigUint,
) -> PaddedBigUint {
    let mut out = lhs.clone();
    let carry = out.add_assign(rhs);
    out.conditional_sub_assign(modulus, Choice::from_lsb(u8::from(carry)));
    out
}

/// CT：`(lhs - rhs) mod modulus`，兩個運算元都必須已經小於模數。
pub(super) fn sub_mod(
    lhs: &PaddedBigUint,
    rhs: &PaddedBigUint,
    modulus: &PaddedBigUint,
) -> PaddedBigUint {
    let mut out = lhs.clone();
    let borrow = out.sub_assign(rhs);
    out.conditional_add_assign(modulus, Choice::from_lsb(u8::from(borrow)));
    out
}

/// CT：`(2 * value) mod modulus`。
pub(super) fn double_mod(value: &PaddedBigUint, modulus: &PaddedBigUint) -> PaddedBigUint {
    let mut out = value.clone();
    double_mod_assign(&mut out, modulus);
    out
}

/// CT：原地把 `value` 加倍並取模。不配置記憶體。
///
/// 直接左移一位取出溢位，比走一次加法少一輪進位傳遞。
pub(super) fn double_mod_assign(value: &mut PaddedBigUint, modulus: &PaddedBigUint) {
    value.assert_same_width(modulus);
    let mut carry = 0 as Word;

    for index in 0..value.len() {
        let word = value.as_limbs()[index].to_word();
        value.as_limbs_mut()[index] = Limb::new((word << 1) | carry);
        carry = word >> (Word::BITS - 1);
    }

    value.conditional_sub_assign(modulus, Choice::from_lsb(carry as u8));
}

/// CT：模數寬度下的 `1 mod modulus`。
pub(super) fn one_mod(modulus: &PaddedBigUint) -> PaddedBigUint {
    let width = modulus.len();
    let mut one = PaddedBigUint::zero_with_limbs(width);
    if width == 0 {
        return one;
    }
    one.as_limbs_mut()[0] = Limb::new(1);

    // 模數至少是 1，所以一次條件減法就夠。
    one.conditional_sub_assign(modulus, Choice::from_lsb(0));
    one
}
