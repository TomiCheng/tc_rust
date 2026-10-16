use super::kernels::impl_mul;
use super::large::KARATSUBA_CUTOFF;
use crate::reduce::Reducer;
use tc_zeroize::Zeroize;

/// BC's scalar `Medium.Multiply`: `z = x · y mod f` for fewer than [`KARATSUBA_CUTOFF`]
/// limbs, the product held on the stack. Variable time, as [`impl_mul`] is.
pub(crate) fn multiply(reducer: &Reducer, x: &[u64], y: &[u64], z: &mut [u64]) {
    let size = x.len();
    debug_assert!(size < KARATSUBA_CUTOFF);
    let mut tt = [0_u64; 2 * (KARATSUBA_CUTOFF - 1)];
    impl_mul(x, y, &mut tt[..2 * size]);
    reducer.reduce(&mut tt[..2 * size], z);
    tt.zeroize();
}

#[cfg(test)]
mod tests {
    use super::super::kernels::{schoolbook, words};
    use super::multiply;
    use crate::reduce::{Reducer, size};

    fn reduced(n: u32, state: &mut u64) -> alloc::vec::Vec<u64> {
        let mut value = words(size(n as usize), state);
        if n & 63 != 0 {
            *value.last_mut().unwrap() &= (1 << (n & 63)) - 1;
        }
        value
    }

    #[test]
    fn the_product_is_the_schoolbook_product_reduced() {
        let mut state = 0x5EED_0163_0233_0409;
        for reducer in [
            Reducer::trinomial(113, 9),
            Reducer::pentanomial(163, 3, 6, 7),
            Reducer::trinomial(233, 74),
            Reducer::pentanomial(283, 5, 7, 12),
            Reducer::trinomial(409, 87),
            Reducer::trinomial(448, 1),
            Reducer::binomial(127),
        ] {
            let n = reducer.n();
            for _ in 0..16 {
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

    #[test]
    fn x_to_the_n_folds_onto_the_lower_terms_of_the_modulus() {
        let reducer = Reducer::pentanomial(163, 3, 6, 7);
        let (mut x, mut y, mut z) = ([0; 3], [0; 3], [0; 3]);
        x[162 / 64] = 1 << (162 % 64);
        y[0] = 0b10;
        multiply(&reducer, &x, &y, &mut z);
        assert_eq!(z, [1 << 7 | 1 << 6 | 1 << 3 | 1, 0, 0]);
    }
}
