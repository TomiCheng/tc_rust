//! 補齊寬度的二補數有號整數，保留全部符號擴展 limb。

use alloc::{boxed::Box, vec};
use core::{cmp::Ordering, fmt};

use crate::{
    BigInt, Choice, ConditionallySelectable, ConstantTimeEq, ConversionError, Limb, Word, Zeroize,
    ZeroizeOnDrop,
};

mod add;
mod bits;
mod checked;
mod convert;
mod div;
mod modular;
mod mul;
mod neg;
mod ops;
#[cfg(feature = "rand_core")]
mod random;
mod shift;
mod sign;
mod str;
mod sub;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod trait_tests;

/// 建構時決定 limb 寬度的二補數有號整數，最高位是符號位。
///
/// 正值保留前導零，負值保留前導一。零寬合法，表示非負的零。
/// 寬度是公開資訊；具名 CT 方法保留寬度，二元 CT 方法嚴格要求同寬。
/// 運算子與數值 trait 是變動時間，只能用於公開值：兩邊以符號擴展
/// 補到最大寬度，算術結果放不下時 panic。
///
/// [`Self::add`]／[`Self::sub`] 回傳的是有號溢位，不是進位或借位。
/// 匯入同名運算子 trait 時，秘密值請用 `PaddedBigInt::add(&a, &b)`
/// 這類完整呼叫避免方法解析歧義。CT 是原始碼層的固定排程約定，
/// 並非每個編譯器與硬體的計時證明。
///
/// 本型別實作 [`ZeroizeOnDrop`]，析構時清除全部 limb；複製或移動留下的
/// 舊副本無法追回。`Debug` 只顯示公開寬度，不顯示數值。
///
/// ```
/// use tc_bigint::{BigInt, PaddedBigInt};
/// let a = PaddedBigInt::from_be_bytes(&[0xff], 4).unwrap();
/// let b = PaddedBigInt::from_be_bytes(&[2], 1).unwrap();
/// assert_eq!((&a + &b).to_big_int(), BigInt::from(1));
/// let (sum, overflow) = PaddedBigInt::add(&a, &b.resize(4).unwrap());
/// assert!(!overflow);
/// assert_eq!(sum.len(), 4);
/// ```
pub struct PaddedBigInt {
    limbs: Box<[Limb]>,
}

impl PaddedBigInt {
    /// CT：建立指定 limb 寬度的零；寬度是公開資訊。
    pub fn zero_with_limbs(limbs: usize) -> Self {
        Self::from_limbs(vec![Limb::new(0); limbs].into_boxed_slice())
    }

    /// CT：建立足以儲存 `bits` 個位元的零，位元數包含符號位。
    pub fn zero_with_bits(bits: usize) -> Self {
        Self::zero_with_limbs(crate::limbs_for_bits(bits))
    }

    /// CT：接管完整二補數儲存，不移除符號擴展位。
    pub(crate) fn from_limbs(limbs: Box<[Limb]>) -> Self {
        Self { limbs }
    }

    /// CT：公開的儲存寬度，以 limb 計。
    pub fn len(&self) -> usize {
        self.limbs.len()
    }

    /// CT：儲存寬度是否為零。
    pub fn is_empty(&self) -> bool {
        self.limbs.is_empty()
    }

    /// CT（末端溢位判定除外）：由大端序二補數建構，以符號位擴展。
    ///
    /// 空輸入代表零。掃描全部輸入後，僅揭露是否能放進指定寬度；
    /// 放不下回 [`ConversionError::InputTooLarge`]，不截斷數值。
    pub fn from_be_bytes(bytes: &[u8], limbs: usize) -> Result<Self, ConversionError> {
        Self::from_bytes(bytes, limbs, true)
    }

    /// CT（末端溢位判定除外）：由小端序二補數建構，契約同 [`Self::from_be_bytes`]。
    pub fn from_le_bytes(bytes: &[u8], limbs: usize) -> Result<Self, ConversionError> {
        Self::from_bytes(bytes, limbs, false)
    }

    fn from_bytes(bytes: &[u8], limbs: usize, big_endian: bool) -> Result<Self, ConversionError> {
        let top = if big_endian {
            bytes.first()
        } else {
            bytes.last()
        };
        let sign = top.copied().unwrap_or(0) >> 7;
        let extension = (0 as Word).wrapping_sub(sign as Word);
        let mut out = Self::from_limbs(vec![Limb::new(extension); limbs].into_boxed_slice());
        let word_bytes = size_of::<Word>();
        let mut overflow = 0_u8;
        for index in 0..bytes.len() {
            let byte = bytes[if big_endian {
                bytes.len() - 1 - index
            } else {
                index
            }];
            let limb = index / word_bytes;
            if limb < limbs {
                let shift = (index % word_bytes) * 8;
                let word = (out.limbs[limb].to_word() & !((0xff as Word) << shift))
                    | ((byte as Word) << shift);
                out.limbs[limb] = Limb::new(word);
            } else {
                overflow |= byte ^ extension as u8;
            }
        }
        overflow |= out.sign_bit() as u8 ^ sign;
        if overflow == 0 {
            Ok(out)
        } else {
            Err(ConversionError::InputTooLarge)
        }
    }

    /// 變動時間：只能用於公開值。把 `BigInt` 以符號擴展補到指定寬度。
    pub fn from_big_int(value: &BigInt, limbs: usize) -> Result<Self, ConversionError> {
        Self::copy_into_width(value.as_limbs(), limbs)
    }

    /// 變動時間：只能用於公開值。轉為最小二補數寬度的 `BigInt`。
    pub fn to_big_int(&self) -> BigInt {
        BigInt::from_limbs(self.limbs.to_vec())
    }

    /// CT（末端溢位判定除外）：建立同值、指定寬度的副本。
    ///
    /// 擴寬補原符號位；縮窄須同時滿足被移除 limb 都是原符號擴展值，
    /// 且保留部分的符號位不變。零寬只容納零。掃描完成後才回傳溢位錯誤。
    pub fn resize(&self, limbs: usize) -> Result<Self, ConversionError> {
        Self::copy_into_width(&self.limbs, limbs)
    }

    fn copy_into_width(source: &[Limb], limbs: usize) -> Result<Self, ConversionError> {
        let sign = source
            .last()
            .map_or(0, |limb| limb.to_word() >> (Word::BITS - 1));
        let extension = (0 as Word).wrapping_sub(sign);
        let mut out = Self::from_limbs(vec![Limb::new(extension); limbs].into_boxed_slice());
        let mut overflow = 0 as Word;
        for (index, limb) in source.iter().enumerate() {
            if index < limbs {
                out.limbs[index] = *limb;
            } else {
                overflow |= limb.to_word() ^ extension;
            }
        }
        overflow |= out.sign_bit() ^ sign;
        if overflow == 0 {
            Ok(out)
        } else {
            Err(ConversionError::InputTooLarge)
        }
    }

    /// CT（末端溢位判定除外）：寫滿大端序二補數輸出，必要時符號擴展。
    ///
    /// 空輸出回 `BufferTooSmall`。縮窄不得改變符號或數值，失敗時輸出保持原狀。
    /// 與 `ArrayEncoding` 的完整儲存寬度寫入不同，本方法採呼叫端指定的寬度。
    pub fn write_be_bytes(&self, out: &mut [u8]) -> Result<(), ConversionError> {
        let extension = self.sign_extension() as u8;
        let mut overflow = u8::from(out.is_empty());
        for index in out.len()..self.len() * size_of::<Word>() {
            overflow |= self.byte_at(index) ^ extension;
        }
        if let Some(top) = out.len().checked_sub(1) {
            overflow |= (self.byte_at(top) >> 7) ^ self.sign_bit() as u8;
        }
        if overflow != 0 {
            return Err(ConversionError::BufferTooSmall);
        }
        for (index, slot) in out.iter_mut().rev().enumerate() {
            *slot = self.byte_at(index);
        }
        Ok(())
    }

    fn byte_at(&self, index: usize) -> u8 {
        let word = self
            .limbs
            .get(index / size_of::<Word>())
            .map_or(self.sign_extension(), |limb| limb.to_word());
        (word >> ((index % size_of::<Word>()) * 8)) as u8
    }

    fn sign_bit(&self) -> Word {
        self.limbs
            .last()
            .map_or(0, |limb| limb.to_word() >> (Word::BITS - 1))
    }

    fn sign_extension(&self) -> Word {
        (0 as Word).wrapping_sub(self.sign_bit())
    }

    /// CT：以 `Choice` 回傳符號位，零寬回假。
    pub fn ct_is_negative(&self) -> Choice {
        Choice::from_lsb(self.sign_bit() as u8)
    }

    /// CT：全寬掃描零值，排程只由公開寬度決定。
    pub fn ct_is_zero(&self) -> Choice {
        let mut aggregate = 0 as Word;
        for limb in &self.limbs {
            aggregate |= limb.to_word();
        }
        aggregate.ct_eq(&0)
    }

    /// 變動時間：只能用於公開值。秘密值請使用 [`Self::ct_is_zero`]。
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|limb| limb.to_word() == 0)
    }

    fn assert_same_width(&self, rhs: &Self) {
        assert_eq!(
            self.len(),
            rhs.len(),
            "padded operands must have the same width"
        );
    }
}

impl Clone for PaddedBigInt {
    /// CT：複製全部儲存，保留寬度。
    fn clone(&self) -> Self {
        Self::from_limbs(self.limbs.clone())
    }
}

/// 僅顯示公開寬度，不顯示數值。
impl fmt::Debug for PaddedBigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaddedBigInt")
            .field("limbs", &self.len())
            .finish_non_exhaustive()
    }
}

/// 變動時間：只能用於公開值。數值相等忽略符號擴展寬度。
impl PartialEq for PaddedBigInt {
    fn eq(&self, rhs: &Self) -> bool {
        self.cmp(rhs) == Ordering::Equal
    }
}
impl Eq for PaddedBigInt {}
/// 變動時間：只能用於公開值。以有號數值比較。
impl PartialOrd for PaddedBigInt {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}
/// 變動時間：只能用於公開值。忽略冗餘符號擴展 limb。
impl Ord for PaddedBigInt {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.to_big_int().cmp(&rhs.to_big_int())
    }
}
impl ConstantTimeEq for PaddedBigInt {
    /// CT：嚴格同寬，寬度不同時 panic；全寬掃描。
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.assert_same_width(rhs);
        let mut aggregate = 0 as Word;
        for index in 0..self.len() {
            aggregate |= self.limbs[index].to_word() ^ rhs.limbs[index].to_word();
        }
        aggregate.ct_eq(&0)
    }
}
impl ConditionallySelectable for PaddedBigInt {
    /// CT：嚴格同寬，寬度不同時 panic；結果保留寬度。
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        a.assert_same_width(b);
        let mut out = Self::zero_with_limbs(a.len());
        for index in 0..a.len() {
            out.limbs[index] = Limb::conditional_select(&a.limbs[index], &b.limbs[index], choice);
        }
        out
    }
}
impl Zeroize for PaddedBigInt {
    /// CT：清除全部 limb，保留原寬。
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}
impl ZeroizeOnDrop for PaddedBigInt {}
impl Drop for PaddedBigInt {
    /// CT：離開作用域時清除全部 limb。
    fn drop(&mut self) {
        self.zeroize();
    }
}
