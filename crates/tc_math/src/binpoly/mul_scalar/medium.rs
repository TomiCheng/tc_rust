//! Scalar leaf backend — bc `Scalar.Medium`.
//!
//! Multiplication is a single leaf carryless multiply ([`super::impl_mul`])
//! followed by the injected reduction. bc routes sizes at or above the Karatsuba
//! cutoff to `Large` instead; that split is not yet ported (leaf covers every NIST
//! binary curve below sect571).

use alloc::boxed::Box;
use alloc::vec;

use crate::binpoly::mul::BinPolyMul;
use crate::binpoly::reduce::Reduce;
use crate::binpoly::size;

use super::kernels::impl_mul;

/// bc `Scalar.Medium`: leaf carryless multiply + reduce.
struct Medium {
    n: usize,
    reduce: Box<dyn Reduce>,
}

impl BinPolyMul for Medium {
    fn n(&self) -> usize {
        self.n
    }

    fn size(&self) -> usize {
        size(self.n)
    }

    fn multiply(&self, x: &[u64], y: &[u64], z: &mut [u64]) {
        let size = self.size();
        debug_assert_eq!(x.len(), size);
        debug_assert_eq!(y.len(), size);
        debug_assert_eq!(z.len(), size);

        let mut tt = vec![0u64; 2 * size]; // 雙倍寬未約簡積
        impl_mul(x, y, &mut tt);
        self.reduce.reduce(&mut tt, z); // 摺回 size limbs
    }
    // square / square_n 用 BinPolyMul trait 的預設
}

/// Builds a boxed [`Medium`] operator over `GF(2ⁿ)` with the given reducer.
/// Called by the scalar backend chooser (bc `Scalar.Backend.CreateBinPolyMul`).
pub(super) fn create(n: usize, reduce: Box<dyn Reduce>) -> Box<dyn BinPolyMul> {
    Box::new(Medium { n, reduce })
}
