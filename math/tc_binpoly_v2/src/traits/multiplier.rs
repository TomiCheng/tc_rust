pub trait BinPolyMul {
    /// Polynomial bit length.
    fn n(&self) -> usize;

    /// Number of limbs in a reduced value.
    fn size(&self) -> usize;

    /// Computes `z = x * y mod r(x)`.
    fn multiply(&self, x: &[u64], y: &[u64], z: &mut [u64]);

    /// Computes `z = x^2 mod r(x)`.
    fn square(&self, x: &[u64], z: &mut [u64]);

    /// Computes `z = x^(2^count) mod r(x)`.
    fn square_n(&self, x: &[u64], count: usize, z: &mut [u64]);
}