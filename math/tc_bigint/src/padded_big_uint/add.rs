//! 保留寬度的加法。

use crate::{Choice, ConditionallySelectable, Limb, PaddedBigUint};

impl PaddedBigUint {
    /// CT：保留寬度的和，外加最高位的進位。
    ///
    /// 排程只由 [`PaddedBigUint::len`] 決定：進位一路傳到最高位，
    /// 不會因為中途沒有進位就提早結束。
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
    /// let value = PaddedBigUint::from_be_bytes(&[255], 1).unwrap();
    /// let (sum, carry) = value.add(&value);
    /// assert_eq!(sum.len(), 1);
    /// assert!(!carry);
    /// ```
    ///
    /// 進位時回傳環繞後的零，不會因數值溢位而 panic。
    ///
    /// ```
    /// use tc_bigint::{PaddedBigUint, limbs_for_bits};
    /// let width = limbs_for_bits(128);
    /// let max = PaddedBigUint::from_be_bytes(&[0xff; 16], width).unwrap();
    /// let one = PaddedBigUint::from_be_bytes(&[1], width).unwrap();
    /// let (wrapped, carry) = PaddedBigUint::add(&max, &one);
    /// assert!(carry);
    /// assert_eq!(wrapped.ct_is_zero().unwrap_u8(), 1);
    /// assert_eq!(wrapped.len(), width);
    /// ```
    ///
    /// CT 加法要求同寬，即使較窄一邊的數值放得下也不自動補零。
    ///
    /// ```should_panic
    /// use tc_bigint::PaddedBigUint;
    /// let narrow = PaddedBigUint::from_be_bytes(&[1], 1).unwrap();
    /// let wide = narrow.resize(2).unwrap();
    /// let _ = PaddedBigUint::add(&narrow, &wide);
    /// ```
    ///
    /// 公開值的 `+` 容忍不同寬度，但最大寬度仍放不下時會 panic。
    /// 秘密值請用上述具名方法，不要改用運算子。
    ///
    /// ```should_panic
    /// use tc_bigint::{PaddedBigUint, limbs_for_bits};
    /// let width = limbs_for_bits(128);
    /// let max = PaddedBigUint::from_be_bytes(&[0xff; 16], width).unwrap();
    /// let one = PaddedBigUint::from_be_bytes(&[1], width).unwrap();
    /// let _ = &max + &one;
    /// ```
    pub fn add(&self, rhs: &Self) -> (Self, bool) {
        self.assert_same_width(rhs);
        let mut out = Self::zero_with_limbs(self.len());
        let mut carry = Limb::new(0);

        for index in 0..self.len() {
            let (sum, next) = self.as_limbs()[index].carrying_add(rhs.as_limbs()[index], carry);
            out.as_limbs_mut()[index] = sum;
            carry = next;
        }

        (out, carry.to_word() != 0)
    }

    /// CT：原地加上 `rhs`，回傳最高位的進位。不配置記憶體。
    ///
    /// # Panics
    ///
    /// 兩個運算元的寬度不同時 panic。
    pub(crate) fn add_assign(&mut self, rhs: &Self) -> bool {
        self.assert_same_width(rhs);
        let mut carry = Limb::new(0);

        for index in 0..self.len() {
            let (sum, next) = self.as_limbs()[index].carrying_add(rhs.as_limbs()[index], carry);
            self.as_limbs_mut()[index] = sum;
            carry = next;
        }

        carry.to_word() != 0
    }

    /// CT：`choice` 為一時原地加上 `rhs`，為零時保持原值。不配置記憶體。
    ///
    /// 兩條路徑的排程相同：加法一律算完，只有寫回與否由 `choice` 無分支地決定。
    /// 回傳的是**實際發生**的進位 —— `choice` 為零時恆為零。
    ///
    /// # Panics
    ///
    /// 兩個運算元的寬度不同時 panic。
    pub(crate) fn conditional_add_assign(&mut self, rhs: &Self, choice: Choice) -> Choice {
        self.assert_same_width(rhs);
        let mut carry = Limb::new(0);

        for index in 0..self.len() {
            let current = self.as_limbs()[index];
            let (sum, next) = current.carrying_add(rhs.as_limbs()[index], carry);
            carry = next;
            self.as_limbs_mut()[index] = Limb::conditional_select(&current, &sum, choice);
        }

        Choice::from_lsb(carry.to_word() as u8) & choice
    }
}
