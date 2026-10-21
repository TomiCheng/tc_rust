//! BC 的 `ECMultiplier`，但基點在建構時就固定：乘法器持有點與它的預算表，`multiply`
//! 只收純量。會不會重複使用只有消費端知道，所以由消費端挑實作；不挑就用 [`PerCall`]。

use crate::Curve;

/// 固定基點的純量乘法。常數時間與否依實作而定，見各實作的說明。
pub trait BaseMultiplier<C: Curve> {
    /// 計算 `scalar` 乘以基點。
    fn multiply(&self, scalar: &C::Scalar) -> C::Point;
}

/// 不留表，每次都呼叫 [`Curve::multiply`]，即目前的行為。常數時間與否沿用該曲線的
/// `multiply`。
pub struct PerCall<C: Curve> {
    point: C::Point,
}

impl<C: Curve> PerCall<C> {
    /// 以 `point` 為基點。常數時間。
    pub fn new(point: C::Point) -> Self {
        Self { point }
    }
}

impl<C: Curve> BaseMultiplier<C> for PerCall<C> {
    fn multiply(&self, scalar: &C::Scalar) -> C::Point {
        C::multiply(&self.point, scalar)
    }
}
