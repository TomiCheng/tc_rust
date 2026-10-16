// Each level down to the cutoff parks its middle product, 2 * ceil(len / 2) limbs, ahead of
// the scratch it hands to its children.
pub(super) fn scratch_size(mut len: usize, cutoff: usize) -> usize {
    debug_assert!(cutoff >= 2);
    let mut total = 0;
    while len >= cutoff {
        len = len.div_ceil(2);
        total += len;
    }
    total * 2
}

// BC's `Large.ImplKaratsuba`, shared by both backends: `zz = x · y` unreduced, `zz` of
// twice the operands' length, `leaf` below `cutoff` limbs. The halved sums are built in
// `zz` where the low product will later land.
pub(super) fn karatsuba<F>(
    x: &[u64],
    y: &[u64],
    zz: &mut [u64],
    scratch: &mut [u64],
    cutoff: usize,
    leaf: &F,
) where
    F: Fn(&[u64], &[u64], &mut [u64]),
{
    let len = x.len();
    if len < cutoff {
        leaf(x, y, zz);
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
        karatsuba(ta, tb, z_mid, child, cutoff, leaf);

        karatsuba(&x[..m], &y[..m], &mut zz[..len], child, cutoff, leaf);
        karatsuba(&x[m..], &y[m..], &mut zz[len..], child, cutoff, leaf);

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
        karatsuba(ta, tb, z_mid, child, cutoff, leaf);

        karatsuba(&x[..n], &y[..n], &mut zz[..2 * n], child, cutoff, leaf);
        karatsuba(&x[n..], &y[n..], &mut zz[2 * n..], child, cutoff, leaf);

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
    use super::super::scalar::kernels::{impl_mul, schoolbook, words};
    use super::{karatsuba, scratch_size};

    #[test]
    fn the_recursion_matches_a_bit_by_bit_schoolbook_for_even_and_odd_halves() {
        let mut state = 0x0DD5_EED5_CA7A_7500;
        for len in 1..=40 {
            for _ in 0..4 {
                let x = words(len, &mut state);
                let y = words(len, &mut state);
                let mut zz = alloc::vec![0; 2 * len];
                let mut scratch = alloc::vec![0; scratch_size(len, 8)];
                karatsuba(&x, &y, &mut zz, &mut scratch, 8, &impl_mul);
                assert_eq!(zz, schoolbook(&x, &y), "len = {len}");
            }
        }
    }

    #[test]
    fn the_scratch_is_two_middle_products_per_level() {
        assert_eq!(scratch_size(7, 8), 0);
        assert_eq!(scratch_size(8, 8), 8);
        assert_eq!(scratch_size(9, 8), 10);
        assert_eq!(scratch_size(16, 8), 24);
        assert_eq!(scratch_size(64, 32), 96);
    }
}
