use tc_constant_time::{ConditionallySelectable, ConstantTimeEq};
use tc_ec_core_v2::BinaryFieldElement;

/// What the curves need of a field element that has no field object to build it from.
/// Sealed: the module is private, so no other crate can name it.
pub trait SecTElement: BinaryFieldElement + ConditionallySelectable + ConstantTimeEq {
    /// The degree m of the field, BC's `FieldSize`.
    const M: usize;

    fn zero() -> Self;

    fn one() -> Self;

    /// `None` when `bytes` are not the field's length or not reduced.
    fn from_be(bytes: &[u8]) -> Option<Self>;

    /// The inverse, or zero for zero, in constant time.
    fn invert_or_zero(&self) -> Self;
}
