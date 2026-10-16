use tc_zeroize::Zeroize;

/// BC's scalar `Kernels.ImplMul`: `zz = x · y` unreduced, for `x` and `y` of the same
/// length and `zz` of twice it. Variable time: the 16-entry table is indexed by bits of the
/// operands, the cache-timing side channel BC accepts for its fallback without CLMUL.
pub(crate) fn impl_mul(x: &[u64], y: &[u64], zz: &mut [u64]) {
    let len = x.len();
    assert_eq!(y.len(), len, "invalid operand length");
    assert_eq!(zz.len(), len * 2, "invalid product length");

    let mut u = [0_u64; 16];
    for i in 0..len {
        let (lo, hi) = mul_word(&mut u, x[i], y[i]);
        zz[2 * i] = lo;
        zz[2 * i + 1] = hi;
    }

    let (mut v0, mut v1) = (zz[0], zz[1]);
    for i in 1..len {
        v0 ^= zz[2 * i];
        zz[i] = v0 ^ v1;
        v1 ^= zz[2 * i + 1];
    }
    let w = v0 ^ v1;
    for i in 0..len {
        zz[len + i] = zz[i] ^ w;
    }

    let last = len - 1;
    for z_pos in 1..last * 2 {
        let mut hi = last.min(z_pos);
        let mut lo = z_pos - hi;
        while lo < hi {
            let (l, h) = mul_word(&mut u, x[lo] ^ x[hi], y[lo] ^ y[hi]);
            zz[z_pos] ^= l;
            zz[z_pos + 1] ^= h;
            lo += 1;
            hi -= 1;
        }
    }
    u.zeroize();
}

// BC's `ImplMulw`: the table holds the multiples of `y` by every 4-bit value; the bits its
// shifts drop off the top are put back into `h` by the repair steps.
fn mul_word(u: &mut [u64; 16], x: u64, y: u64) -> (u64, u64) {
    let (mut h, mut m, mut n) = (0_u64, x, y);
    u[1] = y;
    for i in (2..16).step_by(2) {
        let u_i = u[i / 2] << 1;
        u[i] = u_i;
        u[i + 1] = u_i ^ y;

        m = (m & 0xFEFE_FEFE_FEFE_FEFE) >> 1;
        h ^= m & (((n as i64) >> 63) as u64);
        n <<= 1;
    }

    let j = x as usize;
    let mut l = u[j & 15] ^ (u[(j >> 4) & 15] << 4);
    for k in (8..64).step_by(8) {
        let j = (x >> k) as usize;
        let g = u[j & 15] ^ (u[(j >> 4) & 15] << 4);
        l ^= g << k;
        h ^= g >> (64 - k);
    }
    debug_assert_eq!(h >> 63, 0);
    (l, h)
}

#[cfg(test)]
pub(super) fn schoolbook(x: &[u64], y: &[u64]) -> alloc::vec::Vec<u64> {
    let mut zz = alloc::vec![0_u64; x.len() * 2];
    for (i, &x_i) in x.iter().enumerate() {
        for bit in 0..64 {
            if x_i >> bit & 1 == 0 {
                continue;
            }
            for (j, &y_j) in y.iter().enumerate() {
                zz[i + j] ^= y_j << bit;
                if bit != 0 {
                    zz[i + j + 1] ^= y_j >> (64 - bit);
                }
            }
        }
    }
    zz
}

#[cfg(test)]
pub(super) fn words(len: usize, state: &mut u64) -> alloc::vec::Vec<u64> {
    (0..len)
        .map(|_| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{impl_mul, schoolbook, words};

    #[test]
    fn the_product_matches_a_bit_by_bit_schoolbook() {
        let mut state = 0xB1A2_0F17_5EED_1234;
        for len in 1..=12 {
            for _ in 0..32 {
                let x = words(len, &mut state);
                let y = words(len, &mut state);
                let mut zz = alloc::vec![0; len * 2];
                impl_mul(&x, &y, &mut zz);
                assert_eq!(zz, schoolbook(&x, &y), "len = {len}");
            }
        }
    }

    #[test]
    fn all_ones_words_carry_into_the_top_bit_of_the_low_half() {
        let x = [u64::MAX; 3];
        let mut zz = [0; 6];
        impl_mul(&x, &x, &mut zz);
        assert_eq!(zz.to_vec(), schoolbook(&x, &x));
    }
}
