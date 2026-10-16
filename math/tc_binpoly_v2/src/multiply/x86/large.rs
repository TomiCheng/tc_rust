use super::super::karatsuba::{karatsuba, scratch_size};
use super::kernels::impl_mul;
use crate::reduce::Reducer;
use alloc::vec;
use tc_runtime::intrinsics::x86::Pclmulqdq;
use tc_zeroize::Zeroize;

/// BC's X86.V128 `Large.KaratsubaCutoff`: from this many limbs the product recurses.
pub(crate) const KARATSUBA_CUTOFF: usize = 32;

/// BC's X86.V128 `Large.Multiply`: `z = x · y mod f` by Karatsuba down to [`impl_mul`], the
/// product and the recursion's scratch on the heap. Constant time.
pub(crate) fn multiply(proof: Pclmulqdq, reducer: &Reducer, x: &[u64], y: &[u64], z: &mut [u64]) {
    let size = x.len();
    let mut buffer = vec![0_u64; 2 * size + scratch_size(size, KARATSUBA_CUTOFF)];
    let (tt, scratch) = buffer.split_at_mut(2 * size);
    let leaf = |x: &[u64], y: &[u64], zz: &mut [u64]| impl_mul(proof, x, y, zz);
    karatsuba(x, y, tt, scratch, KARATSUBA_CUTOFF, &leaf);
    reducer.reduce(tt, z);
    buffer[..].zeroize();
}

#[cfg(test)]
mod tests {
    use super::super::super::scalar::kernels::{reduced, schoolbook};
    use super::multiply;
    use crate::reduce::Reducer;
    use tc_runtime::intrinsics::x86::Pclmulqdq;

    #[test]
    fn the_product_is_the_schoolbook_product_reduced() {
        let Some(proof) = Pclmulqdq::detect() else {
            return;
        };
        let mut state = 0x5EED_2048_2500_2323;
        for reducer in [
            Reducer::binomial(2048),
            Reducer::trinomial(2049, 1),
            Reducer::trinomial(2500, 1),
            Reducer::binomial(12323),
        ] {
            let n = reducer.n();
            for _ in 0..2 {
                let x = reduced(n, &mut state);
                let y = reduced(n, &mut state);
                let mut z = alloc::vec![0; x.len()];
                multiply(proof, &reducer, &x, &y, &mut z);

                let mut tt = schoolbook(&x, &y);
                let mut expected = alloc::vec![0; x.len()];
                reducer.reduce(&mut tt, &mut expected);
                assert_eq!(z, expected, "n = {n}");
            }
        }
    }
}
