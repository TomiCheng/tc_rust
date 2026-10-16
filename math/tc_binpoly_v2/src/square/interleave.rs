/// BC's `Interleave.Expand64To128` over a slice: bit `i` of `x` becomes bit `2i` of `zz`,
/// `zz` of twice the length. Constant time.
pub(super) fn expand(x: &[u64], zz: &mut [u64]) {
    for (i, &word) in x.iter().enumerate() {
        let [lo, hi] = expand_word(word);
        zz[2 * i] = lo;
        zz[2 * i + 1] = hi;
    }
}

// Shuffle the low half to the even bits and the high half to the odd ones, then split them.
fn expand_word(mut x: u64) -> [u64; 2] {
    const M64: u64 = 0x5555_5555_5555_5555;
    x = bit_permute_step(x, 0x0000_0000_FFFF_0000, 16);
    x = bit_permute_step(x, 0x0000_FF00_0000_FF00, 8);
    x = bit_permute_step(x, 0x00F0_00F0_00F0_00F0, 4);
    x = bit_permute_step(x, 0x0C0C_0C0C_0C0C_0C0C, 2);
    x = bit_permute_step(x, 0x2222_2222_2222_2222, 1);
    [x & M64, (x >> 1) & M64]
}

// BC's `Bits.BitPermuteStep`: swaps the bits under `mask` with those `shift` above them.
fn bit_permute_step(x: u64, mask: u64, shift: u32) -> u64 {
    let t = (x ^ (x >> shift)) & mask;
    t ^ (t << shift) ^ x
}

#[cfg(test)]
pub(super) fn spread(x: &[u64]) -> alloc::vec::Vec<u64> {
    let mut zz = alloc::vec![0_u64; 2 * x.len()];
    for (i, &word) in x.iter().enumerate() {
        for bit in 0..64 {
            zz[(64 * i + bit) / 32] |= (word >> bit & 1) << (2 * bit % 64);
        }
    }
    zz
}

#[cfg(test)]
mod tests {
    use super::{expand, spread};

    #[test]
    fn expanding_moves_bit_i_to_bit_2i() {
        let x = [0, 1, u64::MAX, 0x8000_0000_0000_0001, 0x0123_4567_89AB_CDEF];
        let mut zz = [0; 10];
        expand(&x, &mut zz);
        assert_eq!(zz.to_vec(), spread(&x));
    }
}
