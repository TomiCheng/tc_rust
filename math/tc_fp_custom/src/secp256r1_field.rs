//! secp256r1 的八個 32-bit limb 欄位核心。
//!
//! 第一版刻意維持 bc `SecP256R1Field` 的 limb 寬度與 Solinas 約簡形狀，
//! 讓移植風險集中在逐行語意對應；64-bit limb 版需要重新推導，留待獨立效能工作。

pub(crate) use crate::specialized_field::gte;

use tc_bigint::modular::mod_odd_inverse;

/// secp256r1 質數體的底層運算。
pub struct SecP256R1Field;

impl SecP256R1Field {
    /// `2^256 - 2^224 + 2^192 + 2^96 - 1`，little-endian 32-bit limbs。
    pub const P: [u32; 8] = [
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0,
        0,
        0,
        1,
        0xffff_ffff,
    ];

    /// 模數內加法。
    pub fn add(left: &[u32; 8], right: &[u32; 8]) -> [u32; 8] {
        let (mut result, carry) = add_words(left, right);
        // This public-value reduction path intentionally reveals the comparison.
        if carry || gte(&result, &Self::P).unwrap_u8() != 0 {
            add_p_inverse_to(&mut result);
        }
        result
    }

    /// 模數內減法。
    pub fn subtract(left: &[u32; 8], right: &[u32; 8]) -> [u32; 8] {
        let (mut result, borrow) = sub_words(left, right);
        if borrow {
            sub_p_inverse_from(&mut result);
        }
        result
    }

    /// 模數內倍增。
    pub fn twice(value: &[u32; 8]) -> [u32; 8] {
        let mut result = [0_u32; 8];
        let mut carry = 0_u32;
        for (output, word) in result.iter_mut().zip(value) {
            let next = *word >> 31;
            *output = (*word << 1) | carry;
            carry = next;
        }
        // This public-value reduction path intentionally reveals the comparison.
        if carry != 0 || gte(&result, &Self::P).unwrap_u8() != 0 {
            add_p_inverse_to(&mut result);
        }
        result
    }

    /// 加法反元素。
    pub fn negate(value: &[u32; 8]) -> [u32; 8] {
        if is_zero(value) {
            [0; 8]
        } else {
            sub_words(&Self::P, value).0
        }
    }

    /// 模數內乘法。
    pub fn multiply(left: &[u32; 8], right: &[u32; 8]) -> [u32; 8] {
        Self::reduce(&multiply_wide(left, right))
    }

    /// 模數內平方。
    pub fn square(value: &[u32; 8]) -> [u32; 8] {
        Self::reduce(&square_wide(value))
    }

    /// 連續平方 `count` 次。
    pub fn square_n(value: &[u32; 8], count: usize) -> [u32; 8] {
        let mut result = *value;
        for _ in 0..count {
            result = Self::square(&result);
        }
        result
    }

    /// 以固定步數 odd-modulus safegcd 計算反元素。
    pub fn invert(value: &[u32; 8]) -> Option<[u32; 8]> {
        let mut result = [0_u32; 8];
        mod_odd_inverse(&Self::P, value, &mut result).then_some(result)
    }

    /// 把 512-bit 乘積以 P-256 的 Solinas 關係折回八個 limbs。
    pub fn reduce(wide: &[u32; 16]) -> [u32; 8] {
        let mut xx08 = i64::from(wide[8]);
        let xx09 = i64::from(wide[9]);
        let xx10 = i64::from(wide[10]);
        let xx11 = i64::from(wide[11]);
        let xx12 = i64::from(wide[12]);
        let xx13 = i64::from(wide[13]);
        let xx14 = i64::from(wide[14]);
        let xx15 = i64::from(wide[15]);
        const N: i64 = 6;
        xx08 -= N;

        let t0 = xx08 + xx09;
        let t1 = xx09 + xx10;
        let t2 = xx10 + xx11 - xx15;
        let t3 = xx11 + xx12;
        let t4 = xx12 + xx13;
        let t5 = xx13 + xx14;
        let t6 = xx14 + xx15;
        let t7 = t5 - t0;

        let mut result = [0_u32; 8];
        let mut carry = i64::from(wide[0]) - t3 - t7;
        result[0] = carry as u32;
        carry >>= 32;
        carry += i64::from(wide[1]) + t1 - t4 - t6;
        result[1] = carry as u32;
        carry >>= 32;
        carry += i64::from(wide[2]) + t2 - t5;
        result[2] = carry as u32;
        carry >>= 32;
        carry += i64::from(wide[3]) + (t3 << 1) + t7 - t6;
        result[3] = carry as u32;
        carry >>= 32;
        carry += i64::from(wide[4]) + (t4 << 1) + xx14 - t1;
        result[4] = carry as u32;
        carry >>= 32;
        carry += i64::from(wide[5]) + (t5 << 1) - t2;
        result[5] = carry as u32;
        carry >>= 32;
        carry += i64::from(wide[6]) + (t6 << 1) + t7;
        result[6] = carry as u32;
        carry >>= 32;
        carry += i64::from(wide[7]) + (xx15 << 1) + xx08 - t2 - t4;
        result[7] = carry as u32;
        carry >>= 32;
        carry += N;
        debug_assert!(carry >= 0);
        reduce32(carry as u32, &mut result);
        result
    }
}

pub(crate) fn is_zero(value: &[u32; 8]) -> bool {
    value.iter().all(|word| *word == 0)
}

pub(crate) fn is_one(value: &[u32; 8]) -> bool {
    value[0] == 1 && value[1..].iter().all(|word| *word == 0)
}

fn add_words(left: &[u32; 8], right: &[u32; 8]) -> ([u32; 8], bool) {
    let mut result = [0_u32; 8];
    let mut carry = 0_u64;
    for index in 0..8 {
        carry += u64::from(left[index]) + u64::from(right[index]);
        result[index] = carry as u32;
        carry >>= 32;
    }
    (result, carry != 0)
}

fn sub_words(left: &[u32; 8], right: &[u32; 8]) -> ([u32; 8], bool) {
    let mut result = [0_u32; 8];
    let mut borrow = 0_u64;
    for index in 0..8 {
        let subtrahend = u64::from(right[index]) + borrow;
        let minuend = u64::from(left[index]);
        result[index] = minuend.wrapping_sub(subtrahend) as u32;
        borrow = u64::from(minuend < subtrahend);
    }
    (result, borrow != 0)
}

fn multiply_wide(left: &[u32; 8], right: &[u32; 8]) -> [u32; 16] {
    let mut result = [0_u32; 16];
    for (left_index, left_word) in left.iter().enumerate() {
        let mut carry = 0_u64;
        for (right_index, right_word) in right.iter().enumerate() {
            let index = left_index + right_index;
            carry += u64::from(*left_word) * u64::from(*right_word) + u64::from(result[index]);
            result[index] = carry as u32;
            carry >>= 32;
        }
        result[left_index + 8] = carry as u32;
    }
    result
}

fn square_wide(value: &[u32; 8]) -> [u32; 16] {
    multiply_wide(value, value)
}

fn reduce32(value: u32, result: &mut [u32; 8]) {
    let mut carry = 0_i64;
    if value != 0 {
        let value = i64::from(value);
        carry += i64::from(result[0]) + value;
        result[0] = carry as u32;
        carry >>= 32;
        if carry != 0 {
            carry += i64::from(result[1]);
            result[1] = carry as u32;
            carry >>= 32;
            carry += i64::from(result[2]);
            result[2] = carry as u32;
            carry >>= 32;
        }
        carry += i64::from(result[3]) - value;
        result[3] = carry as u32;
        carry >>= 32;
        if carry != 0 {
            carry += i64::from(result[4]);
            result[4] = carry as u32;
            carry >>= 32;
            carry += i64::from(result[5]);
            result[5] = carry as u32;
            carry >>= 32;
        }
        carry += i64::from(result[6]) - value;
        result[6] = carry as u32;
        carry >>= 32;
        carry += i64::from(result[7]) + value;
        result[7] = carry as u32;
        carry >>= 32;
        debug_assert!(carry == 0 || carry == 1);
    }
    // This public-value reduction path intentionally reveals the comparison.
    if carry != 0 || gte(result, &SecP256R1Field::P).unwrap_u8() != 0 {
        add_p_inverse_to(result);
    }
}

fn add_p_inverse_to(result: &mut [u32; 8]) {
    let mut carry = i64::from(result[0]) + 1;
    result[0] = carry as u32;
    carry >>= 32;
    if carry != 0 {
        carry += i64::from(result[1]);
        result[1] = carry as u32;
        carry >>= 32;
        carry += i64::from(result[2]);
        result[2] = carry as u32;
        carry >>= 32;
    }
    carry += i64::from(result[3]) - 1;
    result[3] = carry as u32;
    carry >>= 32;
    if carry != 0 {
        carry += i64::from(result[4]);
        result[4] = carry as u32;
        carry >>= 32;
        carry += i64::from(result[5]);
        result[5] = carry as u32;
        carry >>= 32;
    }
    carry += i64::from(result[6]) - 1;
    result[6] = carry as u32;
    carry >>= 32;
    carry += i64::from(result[7]) + 1;
    result[7] = carry as u32;
}

fn sub_p_inverse_from(result: &mut [u32; 8]) {
    let mut carry = i64::from(result[0]) - 1;
    result[0] = carry as u32;
    carry >>= 32;
    if carry != 0 {
        carry += i64::from(result[1]);
        result[1] = carry as u32;
        carry >>= 32;
        carry += i64::from(result[2]);
        result[2] = carry as u32;
        carry >>= 32;
    }
    carry += i64::from(result[3]) + 1;
    result[3] = carry as u32;
    carry >>= 32;
    if carry != 0 {
        carry += i64::from(result[4]);
        result[4] = carry as u32;
        carry >>= 32;
        carry += i64::from(result[5]);
        result[5] = carry as u32;
        carry >>= 32;
    }
    carry += i64::from(result[6]) + 1;
    result[6] = carry as u32;
    carry >>= 32;
    carry += i64::from(result[7]) - 1;
    result[7] = carry as u32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_bigint::{BigUint, ModAdd, ModMul, ModSub};

    fn bigint(words: &[u32]) -> BigUint {
        BigUint::from_le_u32(words)
    }

    #[test]
    fn arithmetic_matches_biguint_mod_p() {
        let modulus = bigint(&SecP256R1Field::P);
        let mut state = 0x5231_F13D_CAFE_0001_u64;
        for _ in 0..256 {
            let mut left = [0_u32; 8];
            let mut right = [0_u32; 8];
            for word in left.iter_mut().chain(right.iter_mut()) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *word = state as u32;
            }
            // This public-value reduction path intentionally reveals the comparison.
            if gte(&left, &SecP256R1Field::P).unwrap_u8() != 0 {
                left = sub_words(&left, &SecP256R1Field::P).0;
            }
            // This public-value reduction path intentionally reveals the comparison.
            if gte(&right, &SecP256R1Field::P).unwrap_u8() != 0 {
                right = sub_words(&right, &SecP256R1Field::P).0;
            }
            let left_big = bigint(&left);
            let right_big = bigint(&right);
            assert_eq!(
                bigint(&SecP256R1Field::add(&left, &right)),
                left_big.mod_add(&right_big, &modulus)
            );
            assert_eq!(
                bigint(&SecP256R1Field::subtract(&left, &right)),
                left_big.mod_sub(&right_big, &modulus)
            );
            assert_eq!(
                bigint(&SecP256R1Field::multiply(&left, &right)),
                left_big.mod_mul(&right_big, &modulus)
            );
            assert_eq!(
                bigint(&SecP256R1Field::square(&left)),
                left_big.mod_mul(&left_big, &modulus)
            );
        }
    }
}
