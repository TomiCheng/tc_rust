//! 補齊寬度的奇模數反元素，走固定步數的 safegcd。

use alloc::vec;
use alloc::vec::Vec;

use super::inverse::mod_odd_inverse;
use crate::{Limb, Odd, PaddedBigUint, Word};

impl PaddedBigUint {
    /// CT（見下方例外）：`self` 對奇模數的乘法反元素，沒有反元素時回 `None`。
    ///
    /// 走 Bernstein-Yang half-delta safegcd，迭代次數只由**公開的模數位元數**
    /// 決定，與 `self` 無關。結果的寬度等於模數寬度。
    ///
    /// `self` 必須小於模數。
    ///
    /// # 已知的常數時間例外
    ///
    /// 底層的 [`mod_odd_inverse`] 在進入迴圈前會用逐字比較確認 `self` 小於模數，
    /// 該比較在第一個相異的字就停止，因此會洩漏兩者最高位相異字的位置。
    /// 對均勻分布的秘密值來說，這幾乎總是最高的那個字，實際資訊量極低，
    /// 但它不是可證明的常數時間。這是既有輔助函式的性質，這裡如實揭露。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = Odd::new(PaddedBigUint::from_be_bytes(&[101], 2).unwrap()).unwrap();
    /// let value = PaddedBigUint::from_be_bytes(&[7], 2).unwrap();
    /// let inverse = value.mod_odd_inverse_ct(&modulus).unwrap();
    /// assert_eq!(inverse.len(), 2);
    /// // 7 * 29 = 203 = 2 * 101 + 1
    /// assert_eq!(inverse, PaddedBigUint::from_be_bytes(&[29], 2).unwrap());
    /// ```
    pub fn mod_odd_inverse_ct(&self, modulus: &Odd<PaddedBigUint>) -> Option<Self> {
        let modulus = modulus.as_ref();
        let width = modulus.len();

        // 模數是公開的，所以在這裡去掉前導零不洩漏秘密。
        let modulus_words = to_u32_words(modulus);
        let significant = modulus_words
            .iter()
            .rposition(|word| *word != 0)
            .map(|index| index + 1)?;

        let mut value_words = to_u32_words(self);
        // 前提是 `self` 小於模數，所以高位一定放得下。
        debug_assert!(value_words[significant..].iter().all(|word| *word == 0));
        value_words.truncate(significant);

        let mut output = vec![0_u32; significant];
        if !mod_odd_inverse(&modulus_words[..significant], &value_words, &mut output) {
            return None;
        }

        Some(from_u32_words(&output, width))
    }
}

/// CT：拆成低位在前的 32 位元字，排程只由寬度決定。
fn to_u32_words(value: &PaddedBigUint) -> Vec<u32> {
    let per_limb = size_of::<Word>() / 4;
    let mut words = Vec::with_capacity(value.len() * per_limb);
    for limb in value.as_limbs() {
        let word = limb.to_word();
        for step in 0..per_limb {
            words.push((word >> (step * 32)) as u32);
        }
    }
    words
}

/// CT：由低位在前的 32 位元字組回 `limbs` 個 limb 寬的值，排程只由寬度決定。
fn from_u32_words(words: &[u32], limbs: usize) -> PaddedBigUint {
    let per_limb = size_of::<Word>() / 4;
    let mut out = PaddedBigUint::zero_with_limbs(limbs);
    for (index, chunk) in words.chunks(per_limb).enumerate() {
        if index >= limbs {
            break;
        }
        let mut word = 0 as Word;
        for (step, part) in chunk.iter().enumerate() {
            word |= (*part as Word) << (step * 32);
        }
        out.as_limbs_mut()[index] = Limb::new(word);
    }
    out
}
