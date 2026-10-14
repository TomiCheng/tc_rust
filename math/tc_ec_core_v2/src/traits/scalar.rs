/// Bit access to an unsigned scalar, as used by scalar recoding and multiplication.
///
/// Every method is variable time and only for public scalars.
pub trait Scalar: Clone {
    /// Number of significant bits; zero has none. Variable time; public values only.
    fn bit_length(&self) -> usize;

    /// Whether bit `index` is set; bits past the length read as zero. Variable time; public values only.
    fn test_bit(&self, index: usize) -> bool;

    /// Whether the scalar is zero. Variable time; public values only.
    fn is_zero(&self) -> bool;

    /// The scalar shifted right by `count` bits. Variable time; public values only.
    fn shr(&self, count: usize) -> Self;

    /// The low `width` bits, i.e. `self mod 2^width`, for `width <= 32`. Variable time; public values only.
    fn low_bits(&self, width: usize) -> u32;
}
