use super::super::karatsuba::{karatsuba, scratch_size};
use super::kernels::impl_mul;
use crate::reduce::Reducer;
use alloc::vec;
use tc_zeroize::Zeroize;

/// BC's scalar `Large.KaratsubaCutoff`: from this many limbs the product recurses.
pub(crate) const KARATSUBA_CUTOFF: usize = 8;

/// BC's scalar `Large.Multiply`: `z = x · y mod f` by Karatsuba down to [`impl_mul`], the
/// product and the recursion's scratch on the heap. Variable time, as [`impl_mul`] is.
pub(crate) fn multiply(reducer: &Reducer, x: &[u64], y: &[u64], z: &mut [u64]) {
    let size = x.len();
    let mut buffer = vec![0_u64; 2 * size + scratch_size(size, KARATSUBA_CUTOFF)];
    let (tt, scratch) = buffer.split_at_mut(2 * size);
    karatsuba(x, y, tt, scratch, KARATSUBA_CUTOFF, &impl_mul);
    reducer.reduce(tt, z);
    buffer[..].zeroize();
}

#[cfg(test)]
mod tests {
    use super::super::kernels::{reduced, schoolbook};
    use super::multiply;
    use crate::reduce::Reducer;

    #[test]
    fn the_product_is_the_schoolbook_product_reduced() {
        let mut state = 0x5EED_0449_0571_1031;
        for reducer in [
            Reducer::trinomial(449, 1),
            Reducer::pentanomial(571, 2, 5, 10),
            Reducer::trinomial(1031, 3),
            Reducer::binomial(2048),
        ] {
            let n = reducer.n();
            for _ in 0..4 {
                let x = reduced(n, &mut state);
                let y = reduced(n, &mut state);
                let mut z = alloc::vec![0; x.len()];
                multiply(&reducer, &x, &y, &mut z);

                let mut tt = schoolbook(&x, &y);
                let mut expected = alloc::vec![0; x.len()];
                reducer.reduce(&mut tt, &mut expected);
                assert_eq!(z, expected, "n = {n}");
            }
        }
    }
}
