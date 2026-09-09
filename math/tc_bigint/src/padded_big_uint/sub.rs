//! 保留寬度的減法。

use crate::{Choice, ConditionallySelectable, Limb, PaddedBigUint};

impl PaddedBigUint {
    /// CT：保留寬度的差，外加最高位的借位。
    ///
    /// 借位代表結果是以 `2^(len * Word::BITS)` 為模的環繞值。排程只由
    /// [`PaddedBigUint::len`] 決定：借位一路傳到最高位，不會提早結束。
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
    /// let zero = PaddedBigUint::zero_with_limbs(1);
    /// let one = PaddedBigUint::from_be_bytes(&[1], 1).unwrap();
    /// let (difference, borrow) = zero.sub(&one);
    /// assert!(borrow);
    /// assert_eq!(difference.len(), 1);
    /// ```
    pub fn sub(&self, rhs: &Self) -> (Self, bool) {
        self.assert_same_width(rhs);
        let mut out = Self::zero_with_limbs(self.len());
        let mut borrow = Limb::new(0);

        for index in 0..self.len() {
            let (difference, next) =
                self.as_limbs()[index].borrowing_sub(rhs.as_limbs()[index], borrow);
            out.as_limbs_mut()[index] = difference;
            borrow = next;
        }

        (out, borrow.to_word() != 0)
    }

    /// CT：原地減去 `rhs`，回傳最高位的借位。不配置記憶體。
    ///
    /// # Panics
    ///
    /// 兩個運算元的寬度不同時 panic。
    pub(crate) fn sub_assign(&mut self, rhs: &Self) -> bool {
        self.assert_same_width(rhs);
        let mut borrow = Limb::new(0);

        for index in 0..self.len() {
            let (difference, next) =
                self.as_limbs()[index].borrowing_sub(rhs.as_limbs()[index], borrow);
            self.as_limbs_mut()[index] = difference;
            borrow = next;
        }

        borrow.to_word() != 0
    }

    /// CT：若 `self >= rhs` 就原地減去 `rhs`，否則保持原值。不配置記憶體。
    ///
    /// `force` 為一時無條件減去，用來處理「和已經溢出最高位」的情形。
    /// 走兩遍：第一遍只算借位以決定要不要減，第二遍才無分支地寫回。
    /// 兩遍的圈數都只由寬度決定。走兩遍是為了不必先配置一個差值再選擇。
    ///
    /// # Panics
    ///
    /// 兩個運算元的寬度不同時 panic。
    pub(crate) fn conditional_sub_assign(&mut self, rhs: &Self, force: Choice) {
        self.assert_same_width(rhs);

        // 第一遍：只算借位。沒有借位代表 `self >= rhs`，該減。
        let mut borrow = Limb::new(0);
        for index in 0..self.len() {
            (_, borrow) = self.as_limbs()[index].borrowing_sub(rhs.as_limbs()[index], borrow);
        }
        // `borrowing_sub` 保證借位是零或一，所以互斥或一就是「沒有借位」。
        let choice = force | Choice::from_lsb((borrow.to_word() ^ 1) as u8);

        // 第二遍：重算差值，依 `choice` 無分支地寫回。
        let mut borrow = Limb::new(0);
        for index in 0..self.len() {
            let current = self.as_limbs()[index];
            let (difference, next) = current.borrowing_sub(rhs.as_limbs()[index], borrow);
            borrow = next;
            self.as_limbs_mut()[index] = Limb::conditional_select(&current, &difference, choice);
        }
    }

    /// CT：`choice` 為一時原地換成 `other`，為零時保持原值。不配置記憶體。
    ///
    /// # Panics
    ///
    /// 兩個運算元的寬度不同時 panic。
    pub(crate) fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        self.assert_same_width(other);
        for index in 0..self.len() {
            let current = self.as_limbs()[index];
            self.as_limbs_mut()[index] =
                Limb::conditional_select(&current, &other.as_limbs()[index], choice);
        }
    }
}
