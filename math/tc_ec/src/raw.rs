//! Low-level limb-array arithmetic — the assembly-like toolbox beneath the
//! headline components, mirroring Bouncy Castle's `Math.Raw` namespace.
//!
//! Currently holds [`Nat`] (fixed-length unsigned integers), the foundation for
//! custom per-size prime-field curves. Future siblings: `interleave` (bit
//! spreading for GF(2ᵐ) squaring), `mod`-style constant-time inversion.

mod nat;

pub use nat::{LIMB_BITS, Limb, Nat, nat_limbs};

// 常用尺寸別名（對齊 bc 的 Nat128…Nat576，以位元數命名）。limb 數由 nat_limbs
// 隨平台自動換算，故同一別名在 64/32/16-bit 上是不同的 Nat<N>。const-generic +
// 單型化取代了 bc 一檔一尺寸的手寫展開。
/// 128-bit [`Nat`]（bc `Nat128`）。
pub type Nat128 = Nat<{ nat_limbs(128) }>;
/// 160-bit [`Nat`]（bc `Nat160`）。
pub type Nat160 = Nat<{ nat_limbs(160) }>;
/// 192-bit [`Nat`]（bc `Nat192`）。
pub type Nat192 = Nat<{ nat_limbs(192) }>;
/// 224-bit [`Nat`]（bc `Nat224`）。
pub type Nat224 = Nat<{ nat_limbs(224) }>;
/// 256-bit [`Nat`]（bc `Nat256`）。
pub type Nat256 = Nat<{ nat_limbs(256) }>;
/// 320-bit [`Nat`]（bc `Nat320`）。
pub type Nat320 = Nat<{ nat_limbs(320) }>;
/// 384-bit [`Nat`]（bc `Nat384`）。
pub type Nat384 = Nat<{ nat_limbs(384) }>;
/// 448-bit [`Nat`]（bc `Nat448`）。
pub type Nat448 = Nat<{ nat_limbs(448) }>;
/// 512-bit [`Nat`]（bc `Nat512`）。
pub type Nat512 = Nat<{ nat_limbs(512) }>;
/// 576-bit [`Nat`]（bc `Nat576`）。
pub type Nat576 = Nat<{ nat_limbs(576) }>;
