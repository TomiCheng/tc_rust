//! Multiplication operator for a binary field `GF(2ⁿ) = GF(2)[x] / r(x)`.
//!
//! Mirrors Bouncy Castle's `IBinPolyMul`: the trait leaves room for the scalar
//! `Medium`/`Large` backends and a future hardware (PCLMUL/PMULL) backend, all
//! selected by a factory. The reduction polynomial is injected as a
//! [`super::reduce::Reduce`]r.

use alloc::boxed::Box;
use alloc::vec;

use super::reduce::Reduce;
use super::{mul_scalar, reduce_pentanomial, reduce_trinomial};

/// Multiplication in `GF(2ⁿ)`, operating on bit-packed `u64`-limb slices. The trait
/// (rather than a concrete type) leaves room for multiple backends (scalar leaf /
/// Karatsuba, and a runtime-selected hardware backend), matching bc's `IBinPolyMul`.
pub trait BinPolyMul {
    /// The field degree `n`.
    fn n(&self) -> usize;

    /// The number of `u64` limbs a field element occupies (`⌈n / 64⌉`).
    fn size(&self) -> usize;

    /// Computes `z = x * y mod r(x)`. All three slices are `size` limbs and must be
    /// distinct.
    fn multiply(&self, x: &[u64], y: &[u64], z: &mut [u64]);

    /// Computes `z = x² mod r(x)`. Defaults to `multiply(x, x, z)` (`x` and `z` must
    /// be distinct).
    // TODO(binpoly-fast-square): a backend can override this with the O(len) bit
    // spread from `raw::interleave` instead of the O(len²) multiply.
    fn square(&self, x: &[u64], z: &mut [u64]) {
        self.multiply(x, x, z);
    }

    /// Computes `z = x^(2^count) mod r(x)` — `count` repeated squarings. Used by the
    /// Itoh–Tsujii inversion addition chain.
    fn square_n(&self, x: &[u64], count: usize, z: &mut [u64]) {
        if count == 0 {
            z.copy_from_slice(x); // x^(2⁰) = x
            return;
        }
        self.square(x, z); // z = x²
        // 無法就地 square(z, z)（借用相交），用一塊 scratch 中轉、再寫回 z。
        let mut tmp = vec![0u64; self.size()];
        for _ in 1..count {
            tmp.copy_from_slice(z);
            self.square(&tmp, z); // z = (上一輪)²
        }
    }
}

/// Builds a multiply operator for `GF(2ⁿ) = GF(2)[x] / (xⁿ + xᵏ + 1)`.
/// Mirrors bc `BinPolys.Mul.Trinomial`.
pub fn create_binpoly_mul_trinomial(n: usize, k: usize) -> Box<dyn BinPolyMul> {
    create_binpoly_mul(n, reduce_trinomial::create(n, k))
}

/// Builds a multiply operator for `GF(2ⁿ) = GF(2)[x] / (xⁿ + xᵏ³ + xᵏ² + xᵏ¹ + 1)`.
/// Mirrors bc `BinPolys.Mul.Pentanomial`.
pub fn create_binpoly_mul_pentanomial(n: usize, k1: usize, k2: usize, k3: usize) -> Box<dyn BinPolyMul> {
    create_binpoly_mul(n, reduce_pentanomial::create(n, k1, k2, k3))
}

/// Backend dispatch: pick a hardware backend when available, else the scalar one.
/// Mirrors bc `BinPolys.Mul.CreateBinPolyMul`.
// TODO(binpoly-simd): on x86_64/aarch64, prefer a PCLMUL/PMULL backend when the CPU
// supports it (runtime feature detection; std-only, or hand-rolled CPUID for no_std).
fn create_binpoly_mul(n: usize, reduce: Box<dyn Reduce>) -> Box<dyn BinPolyMul> {
    mul_scalar::create(n, reduce)
}
