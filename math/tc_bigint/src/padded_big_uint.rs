//! 補齊寬度的無號整數：寬度在建構時決定，之後不再改變。

use alloc::boxed::Box;
use alloc::vec;
use core::fmt;

use crate::traits::BitOps;
use crate::{
    BigUint, Choice, ConditionallySelectable, ConstantTimeEq, ConversionError, Limb, Word, Zeroize,
    ZeroizeOnDrop,
};

mod add;
mod mul;
#[cfg(feature = "rand_core")]
mod random;
mod shift;
mod sub;
#[cfg(test)]
mod tests;

/// 一個無號整數，持有建構時決定的 limb 寬度，並保留全部前導零。
///
/// 它與 [`BigUint`] 的唯一可觀察差異就是**不做正規化**：`BigUint` 會砍掉前導零，
/// 於是配置長度與迴圈次數都隨數值大小改變；本型別的寬度一經建構就固定，
/// 任何運算都不得改變它。常數時間的演算法靠這個性質決定排程。
///
/// # 常數時間約定
///
/// `len()` 是**公開資訊**，可以用來決定迴圈次數；數值本身是秘密。方法分成兩類，
/// 各自的 doc 都會標明屬於哪一類：
///
/// * **CT** —— 排程只由寬度決定，與數值無關。算術、位移、[`ConstantTimeEq`]、
///   [`ConditionallySelectable`]、[`Zeroize`] 都屬於這類。
/// * **變動時間** —— 排程會洩漏數值，doc 會寫明「只能用於公開值」。
///   [`Self::significant_len`]、[`Self::bit_len`]、[`Self::is_zero`]、
///   [`Self::to_big_uint`] 與比較運算子都屬於這類。
///
/// CT 方法的實作內部不得呼叫任何變動時間方法。
///
/// [`fmt::Debug`] 只輸出寬度，不輸出數值，避免秘密值進到記錄。
///
/// # 記憶體清除
///
/// 本型別是 [`ZeroizeOnDrop`]：離開作用域時清除全部 limb。這是
/// [`crate::FixedBigUint`] 為了保持 `Copy` 而放棄的能力。
///
/// # Examples
///
/// ```
/// use tc_bigint::{ConstantTimeEq, Odd, PaddedBigUint};
///
/// // 一個位元組的數值，放進四個 limb 寬的儲存。
/// let value = PaddedBigUint::from_be_bytes(&[7], 4).unwrap();
/// assert_eq!(value.len(), 4);
/// assert_eq!(value.significant_len(), 1);
///
/// // 加法保持寬度。
/// let (sum, carry) = value.add(&value);
/// assert_eq!(sum.len(), 4);
/// assert!(!carry);
///
/// // 前導零不影響數值，也能套進既有的 Odd 包裝。
/// assert!(Odd::new(value.clone()).is_some());
/// assert_eq!(value.ct_eq(&PaddedBigUint::from_be_bytes(&[7], 4).unwrap()).unwrap_u8(), 1);
/// ```
pub struct PaddedBigUint {
    limbs: Box<[Limb]>,
}

impl PaddedBigUint {
    /// CT：建立寬度為 `limbs` 個 limb 的零值。
    pub fn zero_with_limbs(limbs: usize) -> Self {
        Self {
            limbs: vec![Limb::new(0); limbs].into_boxed_slice(),
        }
    }

    /// CT：建立足以容納 `bits` 個位元的零值，寬度為 [`crate::limbs_for_bits`]。
    pub fn zero_with_bits(bits: usize) -> Self {
        Self::zero_with_limbs(crate::limbs_for_bits(bits))
    }

    /// CT：直接接管既有的 limb，寬度即輸入長度。
    pub(crate) fn from_limbs(limbs: Box<[Limb]>) -> Self {
        Self { limbs }
    }

    /// CT（末端的溢位判定除外）：由高位在前的位元組建構，寬度為 `limbs`。
    ///
    /// 掃過全部輸入之後才判定是否溢位；放不下的有效位元回
    /// [`ConversionError::InputTooLarge`]，絕不截斷。
    pub fn from_be_bytes(bytes: &[u8], limbs: usize) -> Result<Self, ConversionError> {
        Self::from_bytes(bytes.iter().rev().copied(), limbs)
    }

    /// CT（末端的溢位判定除外）：由低位在前的位元組建構，寬度為 `limbs`。
    ///
    /// 語意與 [`Self::from_be_bytes`] 相同，只有位元組順序不同。
    pub fn from_le_bytes(bytes: &[u8], limbs: usize) -> Result<Self, ConversionError> {
        Self::from_bytes(bytes.iter().copied(), limbs)
    }

    /// CT（末端的溢位判定除外）：由低位在前的位元組序列建構。
    fn from_bytes(bytes: impl Iterator<Item = u8>, limbs: usize) -> Result<Self, ConversionError> {
        let word_bytes = size_of::<Word>();
        let capacity = limbs * word_bytes;
        let mut out = Self::zero_with_limbs(limbs);
        let mut overflow = 0_u8;

        for (index, byte) in bytes.enumerate() {
            // 位置由公開的輸入長度決定，與數值無關。
            if index < capacity {
                let limb = index / word_bytes;
                let shift = (index % word_bytes) * 8;
                let word = out.limbs[limb].to_word() | ((byte as Word) << shift);
                out.limbs[limb] = Limb::new(word);
            } else {
                overflow |= byte;
            }
        }

        // 契約例外：掃完全部輸入之後，只揭露是否溢位。
        if overflow == 0 {
            Ok(out)
        } else {
            Err(ConversionError::InputTooLarge)
        }
    }

    /// 變動時間：只能用於公開值。由 [`BigUint`] 補零到 `limbs` 個 limb。
    ///
    /// 來源的有效寬度超過 `limbs` 時回 [`ConversionError::InputTooLarge`]。
    /// 之所以是變動時間，是因為 `BigUint` 的內部長度本身就洩漏數值大小。
    pub fn from_big_uint(value: &BigUint, limbs: usize) -> Result<Self, ConversionError> {
        Self::copy_into_width(value.as_limbs(), limbs)
    }

    /// 變動時間：只能用於公開值。轉成會正規化的 [`BigUint`]。
    pub fn to_big_uint(&self) -> BigUint {
        BigUint::from_limbs(self.limbs.to_vec())
    }

    /// CT（末端的溢位判定除外）：換成 `limbs` 個 limb 寬的同值副本。
    ///
    /// 加寬時補零；縮窄時若有效位元放不下，回 [`ConversionError::InputTooLarge`]。
    pub fn resize(&self, limbs: usize) -> Result<Self, ConversionError> {
        Self::copy_into_width(&self.limbs, limbs)
    }

    /// CT（末端的溢位判定除外）：把 `source` 複製進 `limbs` 個 limb 的儲存。
    fn copy_into_width(source: &[Limb], limbs: usize) -> Result<Self, ConversionError> {
        let mut out = Self::zero_with_limbs(limbs);
        let mut overflow = 0 as Word;

        for (index, limb) in source.iter().enumerate() {
            // 位置由公開的兩個寬度決定，與數值無關。
            if index < limbs {
                out.limbs[index] = *limb;
            } else {
                overflow |= limb.to_word();
            }
        }

        // 契約例外：掃完全部來源之後，只揭露是否溢位。
        if overflow == 0 {
            Ok(out)
        } else {
            Err(ConversionError::InputTooLarge)
        }
    }

    /// CT（末端的溢位判定除外）：以高位在前寫滿 `out`，必要時補前導零。
    ///
    /// 與既有的無號編碼一致：零也需要一個位元組，所以空的 `out` 一律失敗。
    /// 有效數值放不下時回 [`ConversionError::BufferTooSmall`]，且 `out` 保持原狀。
    pub fn write_be_bytes(&self, out: &mut [u8]) -> Result<(), ConversionError> {
        let total = self.limbs.len() * size_of::<Word>();
        let mut overflow = u8::from(out.is_empty());

        // 先掃完自己的全部位元組，確認 `out` 裝得下的範圍之外都是零。
        for index in 0..total {
            // 位置由公開的兩個長度決定，與數值無關。
            if index >= out.len() {
                overflow |= self.byte_at(index);
            }
        }

        // 契約例外：掃完之後才揭露是否放得下；失敗時不動 `out`。
        if overflow != 0 {
            return Err(ConversionError::BufferTooSmall);
        }

        for (index, slot) in out.iter_mut().rev().enumerate() {
            *slot = self.byte_at(index);
        }
        Ok(())
    }

    /// CT：取第 `index` 個位元組，低位在前；超出儲存寬度時回零。
    fn byte_at(&self, index: usize) -> u8 {
        let word_bytes = size_of::<Word>();
        let limb = index / word_bytes;
        let shift = (index % word_bytes) * 8;
        match self.limbs.get(limb) {
            Some(limb) => (limb.to_word() >> shift) as u8,
            None => 0,
        }
    }

    /// CT：公開的儲存寬度，以 limb 計。可以用來決定迴圈次數。
    pub fn len(&self) -> usize {
        self.limbs.len()
    }

    /// CT：儲存寬度是否為零。
    pub fn is_empty(&self) -> bool {
        self.limbs.is_empty()
    }

    /// CT：借出全部 limb，長度恆等於 [`Self::len`]。
    pub(crate) fn as_limbs(&self) -> &[Limb] {
        &self.limbs
    }

    /// CT：可變地借出全部 limb，長度恆等於 [`Self::len`]。
    pub(crate) fn as_limbs_mut(&mut self) -> &mut [Limb] {
        &mut self.limbs
    }

    /// 變動時間：只能用於公開值。去掉前導零之後的 limb 數。
    pub fn significant_len(&self) -> usize {
        self.limbs
            .iter()
            .rposition(|limb| limb.to_word() != 0)
            .map_or(0, |index| index + 1)
    }

    /// 變動時間：只能用於公開值。最高位元的位置加一，零回 `0`。
    pub fn bit_len(&self) -> usize {
        match self.limbs.iter().rposition(|limb| limb.to_word() != 0) {
            Some(index) => {
                let leading = self.limbs[index].to_word().leading_zeros();
                index * Word::BITS as usize + (Word::BITS - leading) as usize
            }
            None => 0,
        }
    }

    /// 變動時間：只能用於公開值。秘密值請改用 [`Self::ct_is_zero`]。
    pub fn is_zero(&self) -> bool {
        self.significant_len() == 0
    }

    /// 變動時間：只能用於公開值。無號表示所需的位元組數，零算一個。
    pub fn byte_length_unsigned(&self) -> usize {
        self.bit_len().div_ceil(8).max(1)
    }

    /// CT：第 `index` 個位元，`index` 必須是公開的；超出儲存寬度回 `false`。
    ///
    /// 取值本身沒有資料相依分支，但呼叫端拿這個 `bool` 去分支就會洩漏該位元。
    /// 秘密值請改用 [`Self::bit_choice`]。
    pub fn test_bit(&self, index: usize) -> bool {
        self.bit_word(index) & 1 != 0
    }

    /// CT：第 `index` 個位元，以 [`Choice`] 回傳供無分支選擇使用。
    pub fn bit_choice(&self, index: usize) -> Choice {
        Choice::from_lsb(self.bit_word(index) as u8)
    }

    /// CT：取出含第 `index` 個位元的字，並把該位元移到最低位。
    fn bit_word(&self, index: usize) -> Word {
        let limb = index / Word::BITS as usize;
        let offset = index % Word::BITS as usize;
        match self.limbs.get(limb) {
            Some(limb) => limb.to_word() >> offset,
            None => 0,
        }
    }

    /// CT：值是否為零，排程只由 [`Self::len`] 決定。
    pub fn ct_is_zero(&self) -> Choice {
        let mut aggregate = 0 as Word;
        for limb in self.limbs.iter() {
            aggregate |= limb.to_word();
        }
        aggregate.ct_eq(&0)
    }

    /// CT：把低位段與高位段接成寬度為兩者之和的值。
    pub fn concat(low: &Self, high: &Self) -> Self {
        let mut limbs = vec![Limb::new(0); low.len() + high.len()].into_boxed_slice();
        limbs[..low.len()].copy_from_slice(&low.limbs);
        limbs[low.len()..].copy_from_slice(&high.limbs);
        Self::from_limbs(limbs)
    }

    /// CT：從第 `mid` 個 limb 切成低位與高位兩段。
    ///
    /// `mid` 超過儲存寬度時，高位段的寬度為零。
    pub fn split_at(&self, mid: usize) -> (Self, Self) {
        let mid = mid.min(self.len());
        let (low, high) = self.limbs.split_at(mid);
        (Self::from_limbs(low.into()), Self::from_limbs(high.into()))
    }

    /// 兩個運算元的寬度不同時 panic。寬度是公開資訊，所以用 panic 而不是 `Result`。
    pub(crate) fn assert_same_width(&self, rhs: &Self) {
        assert_eq!(
            self.len(),
            rhs.len(),
            "padded operands must have the same width"
        );
    }
}

impl Clone for PaddedBigUint {
    /// CT：複製全部 limb，保留寬度。
    fn clone(&self) -> Self {
        Self::from_limbs(self.limbs.clone())
    }
}

/// 只輸出公開的儲存寬度，不輸出數值，避免秘密值進到記錄。
impl fmt::Debug for PaddedBigUint {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("PaddedBigUint")
            .field("limbs", &self.limbs.len())
            .finish_non_exhaustive()
    }
}

/// 變動時間：只能用於公開值。數值相等，忽略前導零，寬度不同也可能相等。
impl PartialEq for PaddedBigUint {
    fn eq(&self, rhs: &Self) -> bool {
        self.cmp(rhs) == core::cmp::Ordering::Equal
    }
}

impl Eq for PaddedBigUint {}

impl PartialOrd for PaddedBigUint {
    fn partial_cmp(&self, rhs: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(rhs))
    }
}

/// 變動時間：只能用於公開值。數值比較，忽略前導零。
impl Ord for PaddedBigUint {
    fn cmp(&self, rhs: &Self) -> core::cmp::Ordering {
        let lhs_len = self.significant_len();
        let rhs_len = rhs.significant_len();
        match lhs_len.cmp(&rhs_len) {
            core::cmp::Ordering::Equal => self.limbs[..lhs_len]
                .iter()
                .rev()
                .cmp(rhs.limbs[..rhs_len].iter().rev()),
            ordering => ordering,
        }
    }
}

impl ConstantTimeEq for PaddedBigUint {
    /// CT：排程只由 [`Self::len`] 決定；寬度不同時 panic。
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.assert_same_width(rhs);
        let mut aggregate = 0 as Word;
        for index in 0..self.len() {
            aggregate |= self.limbs[index].to_word() ^ rhs.limbs[index].to_word();
        }
        aggregate.ct_eq(&0)
    }
}

impl ConditionallySelectable for PaddedBigUint {
    /// CT：排程只由寬度決定；寬度不同時 panic。
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        a.assert_same_width(b);
        let mut out = Self::zero_with_limbs(a.len());
        for index in 0..a.len() {
            out.limbs[index] = Limb::conditional_select(&a.limbs[index], &b.limbs[index], choice);
        }
        out
    }
}

impl Zeroize for PaddedBigUint {
    /// CT：清除全部 limb，保留寬度。
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

impl ZeroizeOnDrop for PaddedBigUint {}

impl Drop for PaddedBigUint {
    /// CT：離開作用域時清除全部 limb。
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// 供 [`crate::Odd`] 使用的位元介面。索引必須是公開的，所有操作保留寬度。
///
/// [`Self::bit_length`]、[`Self::bit_count`] 與 [`Self::lowest_set_bit`] 是
/// 變動時間，只能用於公開值。
impl BitOps for PaddedBigUint {
    type Output = Self;

    fn bit_length(&self) -> usize {
        self.bit_len()
    }

    fn bit_count(&self) -> usize {
        self.limbs
            .iter()
            .map(|limb| limb.to_word().count_ones() as usize)
            .sum()
    }

    fn test_bit(&self, index: usize) -> bool {
        PaddedBigUint::test_bit(self, index)
    }

    fn set_bit(&self, index: usize) -> Self {
        self.map_bit(index, |word, mask| word | mask)
    }

    fn clear_bit(&self, index: usize) -> Self {
        self.map_bit(index, |word, mask| word & !mask)
    }

    fn flip_bit(&self, index: usize) -> Self {
        self.map_bit(index, |word, mask| word ^ mask)
    }

    fn lowest_set_bit(&self) -> Option<usize> {
        self.limbs
            .iter()
            .position(|limb| limb.to_word() != 0)
            .map(|index| {
                index * Word::BITS as usize + self.limbs[index].to_word().trailing_zeros() as usize
            })
    }
}

impl PaddedBigUint {
    /// CT：對第 `index` 個位元套用 `operation`，保留寬度。
    ///
    /// # Panics
    ///
    /// `index` 超出儲存寬度時 panic，與 [`crate::FixedBigUint`] 的位元操作一致。
    fn map_bit(&self, index: usize, operation: impl Fn(Word, Word) -> Word) -> Self {
        assert!(
            index < self.len() * Word::BITS as usize,
            "bit index is outside the padded width"
        );
        let mut out = self.clone();
        let limb = index / Word::BITS as usize;
        let mask = (1 as Word) << (index % Word::BITS as usize);
        out.limbs[limb] = Limb::new(operation(out.limbs[limb].to_word(), mask));
        out
    }
}
