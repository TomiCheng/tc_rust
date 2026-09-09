//! 保留寬度的位移。位移量是公開資訊。

use crate::{Limb, PaddedBigUint, Word};

impl PaddedBigUint {
    /// CT：左移 `shift` 個位元，保留寬度；有非零位元被移出頂端時回 `true`。
    ///
    /// `shift` 必須是公開的 —— 排程由它與 [`PaddedBigUint::len`] 決定。
    /// 位移量大於等於總位元數（含 `usize::MAX`）不會 panic，結果為零。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::PaddedBigUint;
    ///
    /// let value = PaddedBigUint::from_be_bytes(&[1], 1).unwrap();
    /// let (shifted, lost) = value.shl(1);
    /// assert!(!lost);
    /// assert_eq!(shifted, PaddedBigUint::from_be_bytes(&[2], 1).unwrap());
    ///
    /// let (_, lost) = value.shl(usize::MAX);
    /// assert!(lost);
    /// ```
    pub fn shl(&self, shift: usize) -> (Self, bool) {
        let width = self.len();
        let bits = Word::BITS as usize;
        let limb_shift = shift / bits;
        let bit_shift = shift % bits;
        let mut out = Self::zero_with_limbs(width);

        for index in 0..width {
            // 來源位置只由公開的位移量與索引決定。
            let word = match index.checked_sub(limb_shift) {
                Some(source) if source < width => {
                    let low = self.as_limbs()[source].to_word() << bit_shift;
                    let carried = if bit_shift == 0 || source == 0 {
                        0
                    } else {
                        self.as_limbs()[source - 1].to_word() >> (bits - bit_shift)
                    };
                    low | carried
                }
                _ => 0,
            };
            out.as_limbs_mut()[index] = Limb::new(word);
        }

        let mut lost = 0 as Word;
        for source in 0..width {
            let word = self.as_limbs()[source].to_word();
            match source.checked_add(limb_shift) {
                // 整個 limb 落在儲存寬度之外。
                None => lost |= word,
                Some(target) if target >= width => lost |= word,
                // 只有最高的 `bit_shift` 個位元會溢出頂端。
                Some(target) if bit_shift != 0 && target + 1 >= width => {
                    lost |= word >> (bits - bit_shift);
                }
                Some(_) => {}
            }
        }

        (out, lost != 0)
    }

    /// CT：右移 `shift` 個位元，保留寬度。
    ///
    /// `shift` 必須是公開的 —— 排程由它與 [`PaddedBigUint::len`] 決定。
    /// 位移量大於等於總位元數（含 `usize::MAX`）不會 panic，結果為零。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::PaddedBigUint;
    ///
    /// let value = PaddedBigUint::from_be_bytes(&[2], 1).unwrap();
    /// assert_eq!(value.shr(1), PaddedBigUint::from_be_bytes(&[1], 1).unwrap());
    /// assert!(value.shr(usize::MAX).is_zero());
    /// ```
    pub fn shr(&self, shift: usize) -> Self {
        let width = self.len();
        let bits = Word::BITS as usize;
        let limb_shift = shift / bits;
        let bit_shift = shift % bits;
        let mut out = Self::zero_with_limbs(width);

        for index in 0..width {
            // 來源位置只由公開的位移量與索引決定。
            let word = match index.checked_add(limb_shift) {
                Some(source) if source < width => {
                    let low = self.as_limbs()[source].to_word() >> bit_shift;
                    let carried = if bit_shift == 0 || source + 1 >= width {
                        0
                    } else {
                        self.as_limbs()[source + 1].to_word() << (bits - bit_shift)
                    };
                    low | carried
                }
                _ => 0,
            };
            out.as_limbs_mut()[index] = Limb::new(word);
        }

        out
    }
}
