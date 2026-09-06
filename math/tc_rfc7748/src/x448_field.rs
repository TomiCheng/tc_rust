//! `GF(2^448 - 2^224 - 1)` 欄位運算，使用 16 個 radix-2²⁸ limb。
//!
//! 表示法與 X25519 的 radix-2²⁵·⁵ 完全不同。所有秘密路徑使用固定次數迴圈；
//! 乘法先做 schoolbook convolution，再利用 `2^448 = 2^224 + 1` 摺疊。
//!
//! 目前刻意只提供 X448 Montgomery ladder 與 DH API 需要的欄位操作。BC 另有
//! `carry`、`cmov`、`normalize`、`reduce`、`is_one`、`sub_one` 及 Ed-facing
//! helpers；那些是 Ed448 點運算／編解碼才會觸發的需求，不是現有 X448 功能
//! 的缺陷。等 Ed448 核心加入時再連同對應 oracle 一起補齊。

/// 欄位元素的 radix-2²⁸ limb 數。
pub const SIZE: usize = 16;

const M28: u32 = 0x0FFF_FFFF;
const RADIX_BITS: usize = 28;
const MODULUS: [u32; SIZE] = {
    let mut p = [M28; SIZE];
    p[8] = M28 - 1;
    p
};

/// X448 欄位元素。每次公開運算都回到 canonical `[0, p)` 表示。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fe448([u32; SIZE]);

#[allow(clippy::should_implement_trait)]
impl Fe448 {
    /// 加法單位元素。
    pub const fn zero() -> Self {
        Self([0; SIZE])
    }

    /// 乘法單位元素。
    pub const fn one() -> Self {
        let mut limbs = [0; SIZE];
        limbs[0] = 1;
        Self(limbs)
    }

    /// 對應 bc `Copy` 的值型別入口。
    pub const fn copy(self) -> Self {
        self
    }

    /// 欄位加法。
    pub fn add(self, rhs: Self) -> Self {
        let coefficients = core::array::from_fn(|i| self.0[i] as u128 + rhs.0[i] as u128);
        Self::reduce_coefficients(coefficients)
    }

    /// 欄位減法。
    pub fn sub(self, rhs: Self) -> Self {
        let mut difference = [0_u32; SIZE];
        let mut borrow = 0_i64;
        for (i, output) in difference.iter_mut().enumerate() {
            let value = self.0[i] as i64 - rhs.0[i] as i64 - borrow;
            *output = value as u32 & M28;
            borrow = (value >> 63) & 1;
        }

        // 若發生 borrow，加入 p；最高 limb 的進位代表減掉一個 2^448，直接捨棄。
        let mask = 0_u32.wrapping_sub(borrow as u32);
        let mut carry = 0_u64;
        for i in 0..SIZE {
            let value = difference[i] as u64 + (MODULUS[i] & mask) as u64 + carry;
            difference[i] = value as u32 & M28;
            carry = value >> RADIX_BITS;
        }
        Self(difference)
    }

    /// 欄位負值。
    pub fn negate(self) -> Self {
        Self::zero().sub(self)
    }

    /// 同時計算 `(self + rhs, self - rhs)`。
    pub fn apm(self, rhs: Self) -> (Self, Self) {
        (self.add(rhs), self.sub(rhs))
    }

    /// 欄位乘法。
    pub fn mul(self, rhs: Self) -> Self {
        let mut product = [0_u128; SIZE * 2];
        for i in 0..SIZE {
            for j in 0..SIZE {
                product[i + j] += self.0[i] as u128 * rhs.0[j] as u128;
            }
        }
        Self::reduce_wide(product)
    }

    /// 乘上一個小整數。
    pub fn mul_u32(self, rhs: u32) -> Self {
        let coefficients = core::array::from_fn(|i| self.0[i] as u128 * rhs as u128);
        Self::reduce_coefficients(coefficients)
    }

    /// 欄位平方。
    pub fn sqr(self) -> Self {
        let mut product = [0_u128; SIZE * 2];
        for i in 0..SIZE {
            let left = self.0[i] as u128;
            product[i * 2] += left * left;
            for j in i + 1..SIZE {
                product[i + j] += (left * self.0[j] as u128) << 1;
            }
        }
        Self::reduce_wide(product)
    }

    /// 重複平方 `n` 次。
    pub fn sqr_n(self, n: usize) -> Self {
        let mut result = self;
        for _ in 0..n {
            result = result.sqr();
        }
        result
    }

    /// 固定 exponent `p - 2` 的反元素；`0` 會映到 `0`。
    pub fn invert(self) -> Self {
        let mut result = Self::one();
        for bit in (0..448).rev() {
            result = result.sqr();
            // p-2 = 2^448 - 2^224 - 3：除了 bit 224 與 bit 1 外皆為 1。
            if bit != 224 && bit != 1 {
                result = result.mul(self);
            }
        }
        result
    }

    /// 常數時間條件交換；`swap` 必須為 0 或 1。
    pub fn cswap(swap: u32, a: Self, b: Self) -> (Self, Self) {
        debug_assert!(swap <= 1);
        let mask = 0_u32.wrapping_sub(swap);
        let mut left = a.0;
        let mut right = b.0;
        for i in 0..SIZE {
            let difference = mask & (left[i] ^ right[i]);
            left[i] ^= difference;
            right[i] ^= difference;
        }
        (Self(left), Self(right))
    }

    /// 判斷 canonical 值是否為零，完整掃過所有 limb。
    pub fn is_zero(self) -> bool {
        let mut difference = 0_u32;
        for limb in self.0 {
            difference |= limb;
        }
        difference == 0
    }

    /// 將 56-byte little-endian 編碼約簡進欄位。
    pub fn decode(bytes: &[u8; 56]) -> Self {
        let mut limbs = [0_u32; SIZE];
        for group in 0..8 {
            let mut packed = [0_u8; 8];
            packed[..7].copy_from_slice(&bytes[group * 7..group * 7 + 7]);
            let word = u64::from_le_bytes(packed);
            limbs[group * 2] = word as u32 & M28;
            limbs[group * 2 + 1] = (word >> RADIX_BITS) as u32;
        }
        Self(Self::subtract_modulus_once(limbs))
    }

    /// 產生 canonical 56-byte little-endian 編碼。
    pub fn encode(self) -> [u8; 56] {
        let limbs = Self::subtract_modulus_once(self.0);
        let mut output = [0_u8; 56];
        for group in 0..8 {
            let word = limbs[group * 2] as u64 | ((limbs[group * 2 + 1] as u64) << 28);
            let bytes = word.to_le_bytes();
            output[group * 7..group * 7 + 7].copy_from_slice(&bytes[..7]);
        }
        output
    }

    fn reduce_wide(mut product: [u128; SIZE * 2]) -> Self {
        // b^16 == b^8 + 1 (mod p)，b = 2^28。由高至低可一併處理再次落在
        // 16..23 的項目。
        for i in (SIZE..SIZE * 2).rev() {
            let value = product[i];
            product[i] = 0;
            product[i - 16] += value;
            product[i - 8] += value;
        }
        let mut coefficients = [0_u128; SIZE];
        coefficients.copy_from_slice(&product[..SIZE]);
        Self::reduce_coefficients(coefficients)
    }

    fn reduce_coefficients(mut coefficients: [u128; SIZE]) -> Self {
        // 固定輪數進位。乘法最壞界限在第二輪後已收斂；保留六輪讓加法與
        // schoolbook 路徑共享同一個容易稽核的核心。
        for _ in 0..6 {
            for i in 0..SIZE - 1 {
                let carry = coefficients[i] >> RADIX_BITS;
                coefficients[i] &= M28 as u128;
                coefficients[i + 1] += carry;
            }
            let carry = coefficients[SIZE - 1] >> RADIX_BITS;
            coefficients[SIZE - 1] &= M28 as u128;
            coefficients[0] += carry;
            coefficients[8] += carry;
        }
        debug_assert!(coefficients.iter().all(|value| *value <= M28 as u128));
        let limbs = core::array::from_fn(|i| coefficients[i] as u32);
        Self(Self::subtract_modulus_once(limbs))
    }

    fn subtract_modulus_once(limbs: [u32; SIZE]) -> [u32; SIZE] {
        let mut difference = [0_u32; SIZE];
        let mut borrow = 0_i64;
        for i in 0..SIZE {
            let value = limbs[i] as i64 - MODULUS[i] as i64 - borrow;
            difference[i] = value as u32 & M28;
            borrow = (value >> 63) & 1;
        }
        let use_difference = (borrow as u32) ^ 1;
        let mask = 0_u32.wrapping_sub(use_difference);
        core::array::from_fn(|i| (difference[i] & mask) | (limbs[i] & !mask))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_bigint::{BigUint, ModSub};

    fn modulus() -> BigUint {
        &(&BigUint::from(1_u8) << 448) - &(&BigUint::from(1_u8) << 224) - BigUint::from(1_u8)
    }

    fn value(element: Fe448) -> BigUint {
        BigUint::from_le_bytes(&element.encode())
    }

    #[test]
    fn arithmetic_matches_biguint_mod_p() {
        let modulus = modulus();
        let mut state = 0x9482_53A7_01D4_C6EB_u64;
        let mut random = || {
            let mut bytes = [0_u8; 56];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            bytes
        };

        for _ in 0..40 {
            let a = Fe448::decode(&random());
            let b = Fe448::decode(&random());
            let av = value(a);
            let bv = value(b);
            assert_eq!(value(a.add(b)), (&av + &bv).rem_euclid(&modulus));
            assert_eq!(value(a.sub(b)), av.mod_sub(&bv, &modulus));
            assert_eq!(value(a.mul(b)), (&av * &bv).rem_euclid(&modulus));
            assert_eq!(value(a.sqr()), (&av * &av).rem_euclid(&modulus));
            if !av.is_zero() {
                assert_eq!(value(a.invert()), av.mod_inverse(&modulus).unwrap());
                assert_eq!(a.mul(a.invert()), Fe448::one());
            }
        }
    }

    #[test]
    fn noncanonical_modulus_decodes_as_zero() {
        let mut bytes = [0_u8; 56];
        bytes.copy_from_slice(&modulus().to_le_bytes());
        assert_eq!(Fe448::decode(&bytes), Fe448::zero());
    }
}
