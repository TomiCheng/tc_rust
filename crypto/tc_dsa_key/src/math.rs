use alloc::vec;
use rand_core::CryptoRng;
use tc_bigint::{ArrayEncoding, Limb, PaddedBigUint, Word};
use tc_zeroize::Zeroize;

/// BC `WNafUtilities.GetNafWeight`：k 的 NAF 中非零位數的個數，也就是 3k XOR k 的 1 位元
/// 數，逐 limb 帶進位計算。常數時間：每個 limb 都走過。
pub(crate) fn naf_weight(limbs: &[Limb]) -> u32 {
    let (mut top, mut carry, mut weight): (Word, Word, u32) = (0, 0, 0);
    for limb in limbs {
        let x = limb.to_word();
        let doubled = (x << 1) | top;
        top = x >> (Word::BITS - 1);
        let (sum, low) = doubled.overflowing_add(x);
        let (sum, high) = sum.overflowing_add(carry);
        carry = Word::from(low) + Word::from(high);
        weight += (sum ^ x).count_ones();
    }
    weight + (top + carry).count_ones()
}

/// BC 的 `new BigInteger(bits, random)`：⌈bits / 8⌉ 個隨機位元組依大端序讀成整數，去掉
/// 最高位元組多出的位元。抽到的位元組用畢清除。常數時間：只依長度。
pub(crate) fn random_bits(rng: &mut dyn CryptoRng, bits: u32) -> PaddedBigUint {
    let length = bits.div_ceil(8) as usize;
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);
    if let Some(first) = bytes.first_mut() {
        *first &= 0xFF >> (length as u32 * 8 - bits);
    }
    let Ok(value) = PaddedBigUint::from_be(&bytes);
    bytes.zeroize();
    value
}

/// BC 的 `BigIntegers.CreateRandomInRange(low, high)` 在 low 很小時的作法：抽 high 的位元數
/// 的隨機值，落在 `[low, high]` 為止。對抽到的值是常數時間：比較不依值分支，丟棄的候選值
/// 清除；只有重抽的次數反映在時間上，與最後的值無關。
pub(crate) fn random_in_range(
    rng: &mut dyn CryptoRng,
    low: &PaddedBigUint,
    high: &PaddedBigUint,
) -> PaddedBigUint {
    loop {
        let mut value = random_bits(rng, high.bits());
        if &value >= low && &value <= high {
            return value;
        }
        value.zeroize();
    }
}
