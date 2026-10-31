use alloc::vec;
use tc_bigint::PaddedBigUint;
use tc_ec_core::{Curve, Point};
use tc_f2m_curve::F2mCtCurve;

/// DSTU 4145 能用的曲線：GF(2^m) 上常數時間的曲線，能報出 m，並能把位元組做成域元素，
/// 以把雜湊放進域裡。`tc_ec_core` 沒有這兩項，所以在這裡補上。
pub trait Dstu4145Curve: Curve<Scalar = PaddedBigUint> {
    /// 域的次數 m，BC 的 `FieldSize`。變動時間：只能用於公開值，m 是公開的。
    fn field_size(&self) -> u32;

    /// 由 ⌈m / 8⌉ 位元組的大端序做出域元素；位元組不是這個長度或超過 m 位元時回傳
    /// `None`。常數時間，除了是否失敗。
    fn element(&self, bytes: &[u8]) -> Option<Self::Field>;
}

impl Dstu4145Curve for &F2mCtCurve {
    /// `tc_f2m_curve` 沒有公開 m，由 `create_point` 拒絕超過 m 位元的座標探出：從
    /// ⌈m / 8⌉ 位元組的最高位元往下，第一個能放的位元就是 m − 1。變動時間：只能用於公開值，
    /// m 是公開的。
    fn field_size(&self) -> u32 {
        let length = self.field_element_encoding_length();
        let zero = vec![0u8; length];
        let top = 8 * length as u32;
        (1..=8)
            .map(|offset| top - offset)
            .find(|&bit| {
                let mut x = zero.clone();
                x[length - 1 - bit as usize / 8] = 1 << (bit % 8);
                F2mCtCurve::create_point(self, &x, &zero).is_ok()
            })
            .map(|bit| bit + 1)
            .expect("an F2m field has a top bit within its last byte")
    }

    /// 以 `create_point` 不檢查曲線的點取出 x，`tc_f2m_curve` 沒有公開別的做法。常數時間，
    /// 除了是否失敗。
    fn element(&self, bytes: &[u8]) -> Option<Self::Field> {
        let zero = vec![0u8; bytes.len()];
        F2mCtCurve::create_point(self, bytes, &zero).ok()?.x()
    }
}
