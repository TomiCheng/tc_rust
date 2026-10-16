use super::kernels::impl_mul;
use super::large::KARATSUBA_CUTOFF;
use crate::reduce::Reducer;
use tc_runtime::intrinsics::x86::Pclmulqdq;
use tc_zeroize::Zeroize;

/// BC's X86.V128 `MediumEven` / `MediumOdd`: `z = x · y mod f` for fewer than
/// [`KARATSUBA_CUTOFF`] limbs, the product held on the stack. Constant time.
pub(crate) fn multiply(proof: Pclmulqdq, reducer: &Reducer, x: &[u64], y: &[u64], z: &mut [u64]) {
    let size = x.len();
    debug_assert!(size < KARATSUBA_CUTOFF);
    let mut buffer = [0_u64; 2 * (KARATSUBA_CUTOFF - 1)];
    let tt = &mut buffer[..2 * size];
    impl_mul(proof, x, y, tt);
    reducer.reduce(tt, z);
    tt.zeroize();
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
        let mut state = 0x5EED_0063_0163_1950;
        for reducer in [
            Reducer::trinomial(63, 1),
            Reducer::binomial(127),
            Reducer::pentanomial(163, 3, 6, 7),
            Reducer::trinomial(233, 74),
            Reducer::pentanomial(571, 2, 5, 10),
            Reducer::trinomial(700, 1),
            Reducer::trinomial(760, 1),
            Reducer::trinomial(1950, 1),
        ] {
            let n = reducer.n();
            for _ in 0..8 {
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
