//! BC 的 `ECMultiplier`，但基點在建構時就固定：乘法器持有點與它的預算表，`multiply`
//! 只收純量。會不會重複使用只有消費端知道，所以由消費端挑實作型別；不挑就用 [`PerCall`]。
//! 基點常在 init 時才隨金鑰到來，所以由使用者（例如簽章器）以 [`BaseMultiplier::new`]
//! 建立，消費端只指定型別。

use crate::Curve;

/// 固定基點的純量乘法。常數時間與否依實作而定，見各實作的說明。
pub trait BaseMultiplier<C: Curve> {
    /// 以 `base` 為基點，並建好它的預算表。
    fn new(base: C::Point) -> Self;

    /// 計算 `scalar` 乘以基點。
    fn multiply(&self, scalar: &C::Scalar) -> C::Point;
}

/// 不留表，每次都呼叫 [`Curve::multiply`]，即目前的行為。常數時間與否沿用該曲線的
/// `multiply`。
pub struct PerCall<C: Curve> {
    point: C::Point,
}

/// `new` 只保存點，常數時間。
impl<C: Curve> BaseMultiplier<C> for PerCall<C> {
    fn new(point: C::Point) -> Self {
        Self { point }
    }

    fn multiply(&self, scalar: &C::Scalar) -> C::Point {
        C::multiply(&self.point, scalar)
    }
}
