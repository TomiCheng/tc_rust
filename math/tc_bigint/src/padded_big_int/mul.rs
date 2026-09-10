//! 私有定長乘法核心，排程只由公開寬度決定。
use crate::{Limb, PaddedBigInt};

impl PaddedBigInt {
    /// CT：同寬乘法，回傳原寬環繞結果與有號溢位，不新增公有乘法入口。
    pub(super) fn mul_core(&self, rhs: &Self) -> (Self, bool) {
        self.assert_same_width(rhs);
        let width = self.len();
        // 暫存也使用會清除的儲存，避免乘積在釋放後殘留。
        let mut wide = Self::zero_with_limbs(2 * width);
        for i in 0..width {
            let mut carry = Limb::new(0);
            for j in 0..width {
                let (low, high) =
                    self.limbs[i].carrying_mul_add(rhs.limbs[j], wide.limbs[i + j], carry);
                wide.limbs[i + j] = low;
                carry = high;
            }
            wide.limbs[i + width] = carry;
        }
        // 二補數有號乘積 = 無號乘積 - sign(a)*b*R - sign(b)*a*R，模 R²。
        let mut borrow_a = Limb::new(0);
        let mut borrow_b = Limb::new(0);
        for j in 0..width {
            let (word, next_a) = wide.limbs[width + j].borrowing_sub(
                Limb::new(rhs.limbs[j].to_word() & self.sign_extension()),
                borrow_a,
            );
            let (word, next_b) = word.borrowing_sub(
                Limb::new(self.limbs[j].to_word() & rhs.sign_extension()),
                borrow_b,
            );
            wide.limbs[width + j] = word;
            borrow_a = next_a;
            borrow_b = next_b;
        }
        let out = Self::from_limbs(wide.limbs[..width].into());
        let mut overflow = 0;
        for limb in &wide.limbs[width..] {
            overflow |= limb.to_word() ^ out.sign_extension();
        }
        (out, overflow != 0)
    }
}
