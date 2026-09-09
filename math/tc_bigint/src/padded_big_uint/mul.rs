//! 保留寬度的完整乘積。

use alloc::vec;

use crate::{Limb, PaddedBigUint};

impl PaddedBigUint {
    /// CT：完整乘積，拆成寬度都等於 `self.len()` 的低位段與高位段。
    ///
    /// 走教科書式的逐 limb 乘加，兩層迴圈的次數都只由
    /// [`PaddedBigUint::len`] 決定，與數值無關；不因為某個 limb 是零就跳過。
    ///
    /// # Panics
    ///
    /// 兩個運算元的寬度不同時 panic。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::PaddedBigUint;
    ///
    /// let value = PaddedBigUint::from_be_bytes(&[3], 2).unwrap();
    /// let (low, high) = value.mul_wide(&value);
    /// assert_eq!(low.len(), 2);
    /// assert_eq!(high.len(), 2);
    /// assert!(high.is_zero());
    /// ```
    pub fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        self.assert_same_width(rhs);
        let width = self.len();
        let mut wide = vec![Limb::new(0); 2 * width];

        for i in 0..width {
            let mut carry = Limb::new(0);
            for j in 0..width {
                let (low, high) =
                    self.as_limbs()[i].carrying_mul_add(rhs.as_limbs()[j], wide[i + j], carry);
                wide[i + j] = low;
                carry = high;
            }
            // 這個位置在本輪之前沒有被寫過，直接放進最後的進位。
            wide[i + width] = carry;
        }

        let high = Self::from_limbs(wide[width..].into());
        wide.truncate(width);
        (Self::from_limbs(wide.into_boxed_slice()), high)
    }
}
