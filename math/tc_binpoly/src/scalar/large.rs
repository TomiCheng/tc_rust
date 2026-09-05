use super::{KARATSUBA_CUTOFF, impl_mul};

/// Scratch words required by [`impl_karatsuba`].
pub(crate) const fn karatsuba_scratch_size(len: usize) -> usize {
    karatsuba_scratch_size_with_cutoff(len, KARATSUBA_CUTOFF)
}

pub(crate) const fn karatsuba_scratch_size_with_cutoff(mut len: usize, cutoff: usize) -> usize {
    let mut total = 0;
    while len >= cutoff {
        let high = (len + 1) >> 1;
        // ta[high] + tb[high] + z_mid[2*high]. Child calls are
        // sequential and share the remaining suffix.
        total += high * 4;
        len = high;
    }
    total
}

/// Safe-slice Karatsuba carryless multiplication.
///
/// Unlike BC's tighter in-output temporary layout, this uses `4*ceil(len/2)`
/// scratch words per live recursion frame. The slightly larger buffer avoids
/// self-aliasing raw pointers while retaining one top-level allocation.
pub(crate) fn impl_karatsuba(x: &[u64], y: &[u64], zz: &mut [u64], scratch: &mut [u64]) {
    impl_karatsuba_with_leaf(x, y, zz, scratch, KARATSUBA_CUTOFF, impl_mul);
}

pub(crate) fn impl_karatsuba_with_leaf<Leaf>(
    x: &[u64],
    y: &[u64],
    zz: &mut [u64],
    scratch: &mut [u64],
    cutoff: usize,
    leaf: Leaf,
) where
    Leaf: Copy + Fn(&[u64], &[u64], &mut [u64]),
{
    assert_eq!(x.len(), y.len());
    assert_eq!(zz.len(), x.len() * 2);
    assert!(cutoff >= 2, "Karatsuba cutoff must be at least two");
    assert!(scratch.len() >= karatsuba_scratch_size_with_cutoff(x.len(), cutoff));

    let len = x.len();
    if len < cutoff {
        leaf(x, y, zz);
        return;
    }

    let low = len >> 1;
    let high = len - low;
    let frame_size = high * 4;
    let (frame, child_scratch) = scratch.split_at_mut(frame_size);
    let (sums, z_mid) = frame.split_at_mut(high * 2);
    let (ta, tb) = sums.split_at_mut(high);

    ta.fill(0);
    tb.fill(0);
    ta[..low].copy_from_slice(&x[..low]);
    tb[..low].copy_from_slice(&y[..low]);
    for i in 0..high {
        ta[i] ^= x[low + i];
        tb[i] ^= y[low + i];
    }

    impl_karatsuba_with_leaf(ta, tb, z_mid, child_scratch, cutoff, leaf);

    let (z0, z2) = zz.split_at_mut(low * 2);
    impl_karatsuba_with_leaf(&x[..low], &y[..low], z0, child_scratch, cutoff, leaf);
    impl_karatsuba_with_leaf(&x[low..], &y[low..], z2, child_scratch, cutoff, leaf);

    // Materialize z_mid ^ z0 ^ z2 before shifting it into zz. Keeping this
    // as a separate pass prevents recombination writes from destroying a z0
    // or z2 limb that a later iteration still needs.
    for i in 0..high * 2 {
        if i < low * 2 {
            z_mid[i] ^= z0[i];
        }
        z_mid[i] ^= z2[i];
    }
    for i in 0..high * 2 {
        zz[low + i] ^= z_mid[i];
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn next(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn karatsuba_matches_scalar_kernel() {
        let mut seed = 0xCA4A_75AB_A5E5_1234_u64;
        for len in KARATSUBA_CUTOFF..=67 {
            let x: Vec<_> = (0..len).map(|_| next(&mut seed)).collect();
            let y: Vec<_> = (0..len).map(|_| next(&mut seed)).collect();
            let mut expected = vec![0_u64; len * 2];
            impl_mul(&x, &y, &mut expected);

            let mut actual = vec![0_u64; len * 2];
            let mut scratch = vec![0_u64; karatsuba_scratch_size(len)];
            impl_karatsuba(&x, &y, &mut actual, &mut scratch);
            assert_eq!(actual, expected, "len={len}");
        }
    }
}
