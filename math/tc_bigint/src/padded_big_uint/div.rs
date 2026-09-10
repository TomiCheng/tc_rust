//! 變動時間：只能用於公開值。除法、餘數與最大公因數委派給 `BigUint`。
use super::ops::{binary_operator, public_result};
use crate::{DivRem, Gcd, PaddedBigUint, RemEuclid};

fn div(a: &PaddedBigUint, b: &PaddedBigUint) -> PaddedBigUint {
    public_result(a.to_big_uint() / b.to_big_uint(), a.len().max(b.len()))
}
fn rem(a: &PaddedBigUint, b: &PaddedBigUint) -> PaddedBigUint {
    public_result(a.to_big_uint() % b.to_big_uint(), a.len().max(b.len()))
}
binary_operator!(
    Div,
    div,
    DivAssign,
    div_assign,
    div,
    "除數為零時 panic；沒有對應的 CT 除法。"
);
binary_operator!(
    Rem,
    rem,
    RemAssign,
    rem_assign,
    rem,
    "除數為零時 panic；沒有對應的 CT 取餘。"
);

/// 變動時間：只能用於公開值。商與餘數的寬度皆為兩邊最大值；除數零時 panic。
impl DivRem for PaddedBigUint {
    type Quotient = Self;
    type Remainder = Self;
    fn div_rem(&self, rhs: &Self) -> (Self, Self) {
        let (q, r) = self.to_big_uint().div_rem(&rhs.to_big_uint());
        let width = self.len().max(rhs.len());
        (public_result(q, width), public_result(r, width))
    }
}
/// 變動時間：只能用於公開值。結果寬度為兩邊最大值；除數零時 panic。
impl RemEuclid for PaddedBigUint {
    type Output = Self;
    fn rem_euclid(&self, rhs: &Self) -> Self {
        rem(self, rhs)
    }
}
/// 變動時間：只能用於公開值。結果寬度為兩邊最大值。
impl Gcd for PaddedBigUint {
    type Output = Self;
    fn gcd(&self, rhs: &Self) -> Self {
        public_result(
            self.to_big_uint().gcd(&rhs.to_big_uint()),
            self.len().max(rhs.len()),
        )
    }
}
