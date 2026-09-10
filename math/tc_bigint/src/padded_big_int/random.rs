//! 變動時間：只能用於公開的位元數與精度。取樣值保持非負。
use crate::{
    BigInt, IsProbablePrime, NextProbablePrime, PaddedBigInt, ProbablePrime, RandomBits,
    RandomBitsError, limbs_for_bits,
};
use rand_core::{Rng, TryRng};

/// 變動時間：只能用於公開的位元數與精度。完整取樣 `0..2^bits`，不丟棄符號位置的隨機位元。
impl RandomBits for PaddedBigInt {
    /// 變動時間：只能用於公開的位元數。寬度為 `limbs_for_bits(bits + 1)`，預留符號位。
    /// 零個隨機位元仍配置符號位，因此得到一個 limb 的零。
    fn try_random_bits<R: TryRng + ?Sized>(
        rng: &mut R,
        bits: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        let storage_bits =
            (bits as usize)
                .checked_add(1)
                .ok_or(RandomBitsError::BitLengthTooLarge {
                    bit_length: bits,
                    bits_precision: u32::MAX,
                })?;
        let value = BigInt::try_random_bits(rng, bits)?;
        Ok(super::ops::public_result(
            value,
            limbs_for_bits(storage_bits),
        ))
    }

    /// 變動時間：只能用於公開的位元數與精度。寬度為 `limbs_for_bits(precision)`。
    /// precision 包含符號位，必須嚴格大於 bits；無號版本則允許相等。
    /// 即使向上補齊 limb 留有空間，也不放寬這個精度契約。參數錯誤不消耗 RNG。
    fn try_random_bits_with_precision<R: TryRng + ?Sized>(
        rng: &mut R,
        bits: u32,
        precision: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        if precision <= bits {
            return Err(RandomBitsError::BitLengthTooLarge {
                bit_length: bits,
                bits_precision: precision,
            });
        }
        let value = BigInt::try_random_bits_with_precision(rng, bits, precision)?;
        Ok(super::ops::public_result(
            value,
            limbs_for_bits(precision as usize),
        ))
    }
}
/// 變動時間：只能用於公開的位元數。生成非負可能質數，寬度預留一個符號位。
/// 這是可能質數生成，並非數學證明。
impl ProbablePrime for PaddedBigInt {
    fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bits: u32) -> Self {
        let storage_bits = (bits as usize).checked_add(1).expect("位元精度溢位");
        super::ops::public_result(
            BigInt::probable_prime(rng, bits),
            limbs_for_bits(storage_bits),
        )
    }
}
/// 變動時間：只能用於公開值。沿用 BigInt 的測試，通過不代表數學證明。
impl IsProbablePrime for PaddedBigInt {
    fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool {
        self.to_big_int().is_probable_prime(certainty, rng)
    }
}
/// 變動時間：只能用於公開值。保留原寬度，下個可能質數放不下時回 `None`。
impl NextProbablePrime for PaddedBigInt {
    type Output = Option<Self>;
    fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Self::Output {
        Self::from_big_int(&self.to_big_int().next_probable_prime(rng), self.len()).ok()
    }
}
