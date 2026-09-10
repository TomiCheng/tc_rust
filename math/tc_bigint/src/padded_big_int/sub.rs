//! 嚴格同寬的有號減法，全寬傳遞借位。
use crate::{Limb, PaddedBigInt};

impl PaddedBigInt {
    /// CT：同寬減法，回傳環繞結果與有號溢位旗標；不同寬 panic。
    ///
    /// 旗標表示異號相減得到與左值不同號的結果，不是無號借位。
    /// 結果寬度不變，排程只由公開寬度決定。
    pub fn sub(&self, rhs: &Self) -> (Self, bool) {
        self.assert_same_width(rhs);
        let mut out = Self::zero_with_limbs(self.len());
        let mut borrow = Limb::new(0);
        for index in 0..self.len() {
            let (difference, next) = self.limbs[index].borrowing_sub(rhs.limbs[index], borrow);
            out.limbs[index] = difference;
            borrow = next;
        }
        let overflow = (self.sign_bit() ^ rhs.sign_bit()) & (self.sign_bit() ^ out.sign_bit());
        (out, overflow != 0)
    }
}
