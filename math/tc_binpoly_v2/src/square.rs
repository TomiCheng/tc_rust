use crate::reduce::Reducer;
use alloc::vec;
use tc_zeroize::Zeroize;

/// BC's `BinPolyMulBase.StackAllocCutoff`: products up to this many limbs stay on the stack.
const STACK_CUTOFF: usize = 128;

/// BC's `BinPolyMulBase.Square`: `z = x² mod f`. Squaring over GF(2) only spreads the bits of
/// `x` to the even positions, so there is no product to compute. Constant time.
pub(crate) fn square(reducer: &Reducer, x: &[u64], z: &mut [u64]) {
    let ext = 2 * x.len();
    if ext <= STACK_CUTOFF {
        let mut tt = [0_u64; STACK_CUTOFF];
        expand_and_reduce(reducer, x, &mut tt[..ext], z);
        tt.zeroize();
    } else {
        let mut tt = vec![0_u64; ext];
        expand_and_reduce(reducer, x, &mut tt, z);
        tt[..].zeroize();
    }
}

fn expand_and_reduce(reducer: &Reducer, x: &[u64], tt: &mut [u64], z: &mut [u64]) {
    for (i, &word) in x.iter().enumerate() {
        let [lo, hi] = expand(word);
        tt[2 * i] = lo;
        tt[2 * i + 1] = hi;
    }
    reducer.reduce(tt, z);
}

// BC's `Interleave.Expand64To128`: shuffle the low half to the even bits and the high half to
// the odd ones, then split them.
fn expand(mut x: u64) -> [u64; 2] {
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
mod tests {
    use super::{expand, square};
    use crate::multiply::Multiplier;
    use crate::reduce::Reducer;

    fn schoolbook_word(x: u64) -> [u64; 2] {
        let mut zz = [0_u64; 2];
        for bit in 0..64 {
            if x >> bit & 1 == 1 {
                zz[2 * bit / 64] |= 1 << (2 * bit % 64);
            }
        }
        zz
    }

    #[test]
    fn expanding_a_word_moves_bit_i_to_bit_2i() {
        for x in [0, 1, u64::MAX, 0x8000_0000_0000_0001, 0x0123_4567_89AB_CDEF] {
            assert_eq!(expand(x), schoolbook_word(x), "x = {x:#x}");
        }
    }

    #[test]
    fn squaring_matches_multiplying_by_itself_on_and_off_the_stack() {
        let mut state = 0x5A0A_2E5E_ED00_0001_u64;
        for reducer in [
            Reducer::trinomial(63, 1),
            Reducer::pentanomial(163, 3, 6, 7),
            Reducer::trinomial(409, 87),
            Reducer::pentanomial(571, 2, 5, 10),
            Reducer::trinomial(4096, 1),
            Reducer::trinomial(4097, 1),
            Reducer::binomial(12323),
        ] {
            let n = reducer.n();
            let size = crate::reduce::size(n as usize);
            let mut x: alloc::vec::Vec<u64> = (0..size)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state
                })
                .collect();
            if n & 63 != 0 {
                x[size - 1] &= (1 << (n & 63)) - 1;
            }

            let mut z = alloc::vec![0; size];
            square(&reducer, &x, &mut z);

            let mut expected = alloc::vec![0; size];
            Multiplier::new(size).multiply(&reducer, &x, &x, &mut expected);
            assert_eq!(z, expected, "n = {n}");
        }
    }
}
