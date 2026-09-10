//! 嚴格同寬的有號加法，全寬傳遞進位。
use crate::{Limb, PaddedBigInt};

impl PaddedBigInt {
    /// CT：同寬加法，回傳環繞結果與有號溢位旗標；不同寬 panic。
    ///
    /// 旗標表示兩個同號輸入得到異號結果，不是無號進位。
    /// 結果寬度不變，排程只由公開寬度決定。
    pub fn add(&self, rhs: &Self) -> (Self, bool) {
        self.assert_same_width(rhs);
        let mut out = Self::zero_with_limbs(self.len());
        let mut carry = Limb::new(0);
        for index in 0..self.len() {
            let (sum, next) = self.limbs[index].carrying_add(rhs.limbs[index], carry);
            out.limbs[index] = sum;
            carry = next;
        }
        let overflow =
            (!(self.sign_bit() ^ rhs.sign_bit()) & (self.sign_bit() ^ out.sign_bit())) & 1;
        (out, overflow != 0)
    }
}
