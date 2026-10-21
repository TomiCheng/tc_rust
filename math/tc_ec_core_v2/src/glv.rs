//! BC 的 `GlvMultiplier`、`EndoUtilities.DecomposeScalar` 與 `ScalarSplitParameters`：有效率
//! 自同態 φ(P) = λP 的曲線上，把 kP 拆成 aP + bφ(P)，a、b 各約 n 的一半長，再以交錯
//! wNAF 計算。φ 由呼叫端提供，core 不必認識各曲線的 β。變動時間，只用於公開純量。
//!
//! 與 BC 一樣，結果只對階 n 的子群中的點成立：φ(P) = λP 只在那裡成立。

mod mul;
mod split;

pub use mul::GlvTable;
pub use mul::glv_mul;
pub use mul::glv_mul_point;
pub use split::ScalarSplit;
