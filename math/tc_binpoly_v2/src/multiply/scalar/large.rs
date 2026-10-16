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
    let mut buffer = vec![0_u64; 2 * size + scratch_size(size)];
    let (tt, scratch) = buffer.split_at_mut(2 * size);
    karatsuba(x, y, tt, scratch);
    reducer.reduce(tt, z);
    buffer[..].zeroize();
}

// Each level down to the cutoff parks its middle product, 2 * ceil(len / 2) limbs, ahead of
// the scratch it hands to its children.
fn scratch_size(mut len: usize) -> usize {
    let mut total = 0;
    while len >= KARATSUBA_CUTOFF {
        len = len.div_ceil(2);
        total += len;
    }
    total * 2
}

// BC's `ImplKaratsuba`: `zz = x · y` unreduced, `zz` of twice the operands' length. The
// halved sums are built in `zz` where the low product will later land.
fn karatsuba(x: &[u64], y: &[u64], zz: &mut [u64], scratch: &mut [u64]) {
    let len = x.len();
    if len < KARATSUBA_CUTOFF {
        impl_mul(x, y, zz);
        return;
    }

    if len & 1 == 0 {
        let m = len / 2;
        let (z_mid, child) = scratch.split_at_mut(2 * m);
        for i in 0..m {
            zz[i] = x[i] ^ x[m + i];
            zz[m + i] = y[i] ^ y[m + i];
        }
        let (ta, tb) = zz[..2 * m].split_at(m);
        karatsuba(ta, tb, z_mid, child);

        karatsuba(&x[..m], &y[..m], &mut zz[..len], child);
        karatsuba(&x[m..], &y[m..], &mut zz[len..], child);

        for i in 0..m {
            let u = zz[m + i] ^ zz[len + i];
            zz[m + i] = u ^ zz[i] ^ z_mid[i];
            zz[len + i] = u ^ zz[len + m + i] ^ z_mid[m + i];
        }
    } else {
        let n = len / 2;
        let m = n + 1;
        let (z_mid, child) = scratch.split_at_mut(2 * m);
        for i in 0..n {
            zz[i] = x[i] ^ x[n + i];
            zz[m + i] = y[i] ^ y[n + i];
        }
        zz[n] = x[2 * n];
        zz[m + n] = y[2 * n];
        let (ta, tb) = zz[..2 * m].split_at(m);
        karatsuba(ta, tb, z_mid, child);

        karatsuba(&x[..n], &y[..n], &mut zz[..2 * n], child);
        karatsuba(&x[n..], &y[n..], &mut zz[2 * n..], child);

        for i in 0..n {
            let u = zz[n + i] ^ zz[2 * n + i];
            zz[n + i] = u ^ zz[i] ^ z_mid[i];
            zz[2 * n + i] = u ^ zz[3 * n + i] ^ z_mid[n + i];
        }
        zz[3 * n] ^= z_mid[2 * n] ^ zz[4 * n];
        zz[3 * n + 1] ^= z_mid[2 * n + 1] ^ zz[4 * n + 1];
    }
}

#[cfg(test)]
mod tests {
    use super::super::kernels::{reduced, schoolbook, words};
    use super::{karatsuba, multiply, scratch_size};
    use crate::reduce::Reducer;

    #[test]
    fn the_recursion_matches_a_bit_by_bit_schoolbook_for_even_and_odd_halves() {
        let mut state = 0x0DD5_EED5_CA7A_7500;
        for len in 1..=40 {
            for _ in 0..4 {
                let x = words(len, &mut state);
                let y = words(len, &mut state);
                let mut zz = alloc::vec![0; 2 * len];
                let mut scratch = alloc::vec![0; scratch_size(len)];
                karatsuba(&x, &y, &mut zz, &mut scratch);
                assert_eq!(zz, schoolbook(&x, &y), "len = {len}");
            }
        }
    }

    #[test]
    fn the_scratch_is_two_middle_products_per_level() {
        assert_eq!(scratch_size(7), 0);
        assert_eq!(scratch_size(8), 8);
        assert_eq!(scratch_size(9), 10);
        assert_eq!(scratch_size(16), 24);
    }

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
