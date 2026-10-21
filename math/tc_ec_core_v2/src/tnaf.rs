//! BC 的 `Tnaf` 與 `WTauNafMultiplier`：Koblitz 二元曲線的 reduced width-4 τ-adic NAF
//! 乘法。τ(P) = (x², y²) 由呼叫端提供，core 不必認識二元體。變動時間，只用於公開純量。
//!
//! 與 BC 一樣，結果只對階 n 的子群中的點成立：純量先對 δ = (τ^m - 1) / (τ - 1) 約簡，而 δ
//! 只消去這個子群。驗證點是否在子群裡，不能經過這裡。

mod digits;
mod reduction;
mod table;

pub use table::WTauNafTable;
pub use table::is_koblitz;
pub use table::wtnaf_mul;
pub use table::wtnaf_mul_point;

// BC `Tnaf.Width`。
const WIDTH: u32 = 4;
// BC `WTauNafMultiplier` 傳給 `PartModReduction` 的精度 c。
const PRECISION: u32 = 10;
