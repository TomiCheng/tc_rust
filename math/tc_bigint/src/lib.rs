#![no_std]
//! 6 個小端序大整數型別，分成 3 對。
//!
//! [`BigUint`]／[`BigInt`] 的長度隨數值變動，需要 `alloc`，不適合常數時間路徑。
//! [`FixedBigUint<N>`]／[`FixedBigInt<N>`] 的寬度是型別參數，實作 `Copy`；
//! 算術與呼叫端緩衝編碼不配置，停用預設功能後仍可使用。
//! [`PaddedBigUint`]／[`PaddedBigInt`] 的固定寬度是執行期值，儲存在堆上，
//! 需要 `alloc`，並實作 [`ZeroizeOnDrop`]；秘密值使用其具名 CT 方法。
//!
//! # Widths
//!
//! Name the fixed-width types through the bit-width aliases rather than a limb
//! count: limb width follows the target and is not part of the public API.
//!
//! ```
//! use tc_bigint::{U256, U2048};
//! assert_eq!(size_of::<U256>() * 8, 256);
//! assert_eq!(size_of::<U2048>() * 8, 2048);
//! ```
//!
//! Padded 型別不用型別別名指定寬度：以 [`limbs_for_bits(bits)`](limbs_for_bits)
//! 計算 limb 數，或直接使用 [`PaddedBigUint::zero_with_bits`]／
//! [`PaddedBigInt::zero_with_bits`]；有號型別的位元數包含符號位。
//!
//! # Representation
//!
//! Signed values use two's complement. Conversions name their byte order, so
//! callers choose it explicitly instead of inheriting an internal layout.
//!
//! ```
//! use tc_bigint::{ArrayEncoding, U64};
//! let value = U64::from_be_bytes(&[0x01, 0x02]).unwrap();
//! assert_eq!(value.to_be_bytes(), [0, 0, 0, 0, 0, 0, 0x01, 0x02]);
//! assert_eq!(value.to_le_bytes(), [0x02, 0x01, 0, 0, 0, 0, 0, 0]);
//! ```
//!
//! # Traits
//!
//! The numeric traits are defined here rather than taken from `num-traits`,
//! and are not type-compatible with `num_traits::*`. They are grouped by role:
//! identities and bound aggregators, big-integer operations, overflow
//! policies, primitive conversion, slice conversion, and randomised
//! construction. The crate README lists which of the six types implements
//! each one.
//!
//! # Explicit erasure
//!
//! 六個整數型別皆實作 [`Zeroize`]。`PaddedBigUint`／`PaddedBigInt` 另實作
//! [`ZeroizeOnDrop`]，析構時清除全部 limb；其餘四個型別由呼叫端選擇清除政策，
//! 例如以 [`Zeroizing`] 包裝秘密值。
//!
//! Erasure of the `Fixed*` pair overwrites every limb. These types remain `Copy` and
//! cannot implement `Drop`: clearing one binding does not erase other copies.
//! Dynamic-width erasure overwrites the current live limbs before clearing the
//! vector length to restore canonical zero, then clears spare capacity. It
//! retains the current allocation for reuse but cannot reach inaccessible buffers
//! left by earlier reallocations. Neither path erases copies left elsewhere by
//! moves, the compiler, or the operating system. See [`tc_zeroize`] for the mechanism
//! and its limitations.
//!
//! ```
//! use tc_bigint::{U256, Zeroize, Zeroizing};
//! let mut scratch = U256::from(7_u8);
//! scratch.zeroize();
//! assert!(scratch.is_zero());
//! let _secret = Zeroizing::new(U256::from(9_u8));
//! ```
//!
//! # Features
//!
//! `alloc` and `rand_core` are on by default. Use
//! `default-features = false, features = ["rand_core"]` for fixed-width random
//! and prime operations without an allocator, or disable both for fixed-width
//! arithmetic only.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
pub use tc_zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
#[cfg(feature = "alloc")]
mod big_int;
#[cfg(feature = "alloc")]
mod big_uint;
mod encoding;
mod error;
mod fixed_big_int;
mod fixed_big_uint;
mod format;
mod limb;
pub mod modular;
mod non_zero;
mod odd;
mod ops_forward;
#[cfg(feature = "alloc")]
mod padded_big_int;
#[cfg(feature = "alloc")]
mod padded_big_uint;
#[cfg(feature = "rand_core")]
mod prime;
mod traits;
mod types;

#[cfg(feature = "alloc")]
pub use big_int::BigInt;
#[cfg(feature = "alloc")]
pub use big_uint::BigUint;
#[cfg(feature = "rand_core")]
pub use error::RandomBitsError;
pub use error::{ConversionError, ParseBigIntError};
pub use fixed_big_int::FixedBigInt;
pub use fixed_big_uint::FixedBigUint;
pub(crate) use limb::array::LimbArray;
pub(crate) use limb::{Limb, WideWord, Word};
pub use non_zero::NonZero;
pub use odd::Odd;
#[cfg(feature = "alloc")]
pub use padded_big_int::PaddedBigInt;
#[cfg(feature = "alloc")]
pub use padded_big_uint::PaddedBigUint;
#[cfg(feature = "rand_core")]
pub use rand_core;
#[cfg(feature = "alloc")]
pub use traits::ToStrRadix;
pub use traits::{
    AndNot, ArrayEncoding, BitOps, Bounded, CheckedAdd, CheckedDiv, CheckedMul, CheckedNeg,
    CheckedRem, CheckedShl, CheckedShr, CheckedSub, DivRem, FromPrimitive, Gcd, ModAdd, ModInverse,
    ModMul, ModPow, ModSub, Num, NumAssign, NumAssignOps, NumAssignRef, NumOps, NumRef, One,
    OverflowingAdd, OverflowingMul, OverflowingSub, Pow, RefNum, RemEuclid, SaturatingAdd,
    SaturatingMul, SaturatingSub, Signed, Square, ToPrimitive, Unsigned, WrappingAdd, WrappingMul,
    WrappingNeg, WrappingSub, Zero,
};
#[cfg(feature = "rand_core")]
pub use traits::{
    IsProbablePrime, NextProbablePrime, ProbablePrime, Random, RandomBits, RandomMod,
};
pub use types::limbs_for_bits;
pub use types::{
    I64, I128, I1024, U64, U128, U256, U384, U512, U521, U1024, U1536, U2048, U3072, U4096,
};
