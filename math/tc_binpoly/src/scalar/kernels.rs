/// Computes the unreduced carryless product of equally-sized limb slices.
///
/// The implementation follows Bouncy Castle's scalar `Kernels.ImplMul`: a
/// 16-entry table implements each 64-by-64 carryless product, while the
/// diagonal/cross-product arrangement reduces the number of leaf products.
/// `zz` must contain exactly twice as many limbs as either input.
pub fn impl_mul(x: &[u64], y: &[u64], zz: &mut [u64]) {
    assert_eq!(x.len(), y.len(), "input lengths differ");
    assert_eq!(
        zz.len(),
        x.len() * 2,
        "output length must be twice the input length"
    );

    let len = x.len();
    if len == 0 {
        return;
    }

    let mut table = [0_u64; 16];

    for i in 0..len {
        let (lo, hi) = impl_mul_word(&mut table, x[i], y[i]);
        zz[i << 1] = lo;
        zz[(i << 1) + 1] = hi;
    }

    let mut v0 = zz[0];
    let mut v1 = zz[1];
    for i in 1..len {
        v0 ^= zz[i << 1];
        zz[i] = v0 ^ v1;
        v1 ^= zz[(i << 1) + 1];
    }

    let streak = v0 ^ v1;
    for i in 0..len {
        zz[len + i] = zz[i] ^ streak;
    }

    let last = len - 1;
    for z_pos in 1..last * 2 {
        let mut hi = core::cmp::min(last, z_pos);
        let mut lo = z_pos - hi;
        while lo < hi {
            let (p0, p1) = impl_mul_word(&mut table, x[lo] ^ x[hi], y[lo] ^ y[hi]);
            zz[z_pos] ^= p0;
            zz[z_pos + 1] ^= p1;
            lo += 1;
            hi -= 1;
        }
    }
}

/// Carryless 64-by-64 multiplication using a 16-entry nibble table.
#[inline]
fn impl_mul_word(table: &mut [u64; 16], x: u64, y: u64) -> (u64, u64) {
    let mut high = 0_u64;
    let mut repair_x = x;
    let mut repair_y = y;

    table[0] = 0;
    table[1] = y;
    for i in (2..16).step_by(2) {
        let value = table[i / 2] << 1;
        table[i] = value;
        table[i + 1] = value ^ y;

        // Repair the high bits lost by the truncated table shifts.
        repair_x = (repair_x & 0xFEFE_FEFE_FEFE_FEFE) >> 1;
        high ^= repair_x & (((repair_y as i64) >> 63) as u64);
        repair_y <<= 1;
    }

    let mut window = x as u32;
    let mut low = table[(window & 15) as usize] ^ (table[((window >> 4) & 15) as usize] << 4);

    let mut shift = 56_u32;
    loop {
        window = (x >> shift) as u32;
        let value = table[(window & 15) as usize] ^ (table[((window >> 4) & 15) as usize] << 4);
        low ^= value << shift;
        high ^= value >> (64 - shift);
        if shift == 8 {
            break;
        }
        shift -= 8;
    }

    debug_assert_eq!(high >> 63, 0);
    (low, high)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn reference(x: &[u64], y: &[u64]) -> Vec<u64> {
        let mut zz = vec![0_u64; x.len() * 2];
        for (i, &x_i) in x.iter().enumerate() {
            for bit in 0..64 {
                if x_i & (1_u64 << bit) == 0 {
                    continue;
                }
                for (j, &y_j) in y.iter().enumerate() {
                    let word = i + j;
                    zz[word] ^= y_j << bit;
                    if bit != 0 {
                        zz[word + 1] ^= y_j >> (64 - bit);
                    }
                }
            }
        }
        zz
    }

    fn next(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn impl_mul_matches_bit_by_bit_schoolbook() {
        let mut seed = 0xB1A2_0F17_5EED_1234_u64;
        for len in 1..=12 {
            for _ in 0..64 {
                let x: Vec<_> = (0..len).map(|_| next(&mut seed)).collect();
                let y: Vec<_> = (0..len).map(|_| next(&mut seed)).collect();
                let expected = reference(&x, &y);
                let mut actual = vec![0_u64; len * 2];
                impl_mul(&x, &y, &mut actual);
                assert_eq!(actual, expected, "len={len}");
            }
        }
    }

    #[test]
    fn impl_mul_handles_zero_length() {
        impl_mul(&[], &[], &mut []);
    }
}
