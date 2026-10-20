// The intrinsic is unsafe before Rust 1.87 and safe inside these functions after it.
#![allow(unused_unsafe)]

use core::arch::x86_64::{_pdep_u64, _pext_u64};
use tc_runtime::intrinsics::x86::Bmi2X64;

const EVEN: u64 = 0x5555_5555_5555_5555;
const ODD: u64 = 0xAAAA_AAAA_AAAA_AAAA;

// BC's `Interleave.Expand64To128` on its BMI2 path over a slice, `zz` of twice its length:
// one PDEP per half word. Constant time where PDEP is; AMD before Zen 3 runs it in
// microcode, slowly.
pub(crate) fn expand(_proof: Bmi2X64, x: &[u64], zz: &mut [u64]) {
    assert_eq!(zz.len(), 2 * x.len(), "the expansion is twice the length");
    // SAFETY: the proof shows the CPU has BMI2 in 64-bit mode.
    unsafe { expand_pdep(x, zz) }
}

// BC's `Interleave.Unshuffle(x, out even)` on its BMI2 path: [odd, even] by two PEXTs.
pub(crate) fn unshuffle(_proof: Bmi2X64, x: u64) -> [u64; 2] {
    // SAFETY: the proof shows the CPU has BMI2 in 64-bit mode.
    unsafe { unshuffle_pext(x) }
}

// BC's `Interleave.Unshuffle(x0, x1, out even)` on its BMI2 path: [odd, even] of `x1:x0`.
pub(crate) fn unshuffle_pair(_proof: Bmi2X64, x0: u64, x1: u64) -> [u64; 2] {
    // SAFETY: the proof shows the CPU has BMI2 in 64-bit mode.
    let ([o0, e0], [o1, e1]) = unsafe { (unshuffle_pext(x0), unshuffle_pext(x1)) };
    [o0 | (o1 << 32), e0 | (e1 << 32)]
}

#[target_feature(enable = "bmi2")]
unsafe fn expand_pdep(x: &[u64], zz: &mut [u64]) {
    for (i, &word) in x.iter().enumerate() {
        unsafe {
            zz[2 * i] = _pdep_u64(word, EVEN);
            zz[2 * i + 1] = _pdep_u64(word >> 32, EVEN);
        }
    }
}

#[target_feature(enable = "bmi2")]
unsafe fn unshuffle_pext(x: u64) -> [u64; 2] {
    unsafe { [_pext_u64(x, ODD), _pext_u64(x, EVEN)] }
}

#[cfg(test)]
mod tests {
    use super::expand;
    use super::{unshuffle, unshuffle_pair};
    use crate::interleave::{expand64_to128, unshuffle_word};
    use tc_runtime::intrinsics::x86::Bmi2X64;

    const WORDS: [u64; 5] = [0, 1, u64::MAX, 0x8000_0000_0000_0001, 0x0123_4567_89AB_CDEF];

    #[test]
    fn pext_splits_odd_and_even_bits_as_the_scalar_steps_do() {
        let Some(proof) = Bmi2X64::detect() else {
            return;
        };
        for x0 in WORDS {
            let u0 = unshuffle_word(x0);
            assert_eq!(unshuffle(proof, x0), [u0 >> 32, u0 & 0xFFFF_FFFF]);
            for x1 in WORDS {
                let u1 = unshuffle_word(x1);
                assert_eq!(
                    unshuffle_pair(proof, x0, x1),
                    [
                        (u0 >> 32) | (u1 & 0xFFFF_FFFF_0000_0000),
                        (u1 << 32) | (u0 & 0xFFFF_FFFF)
                    ]
                );
            }
        }
    }

    #[test]
    fn pdep_moves_bit_i_to_bit_2i_as_the_scalar_steps_do() {
        let Some(proof) = Bmi2X64::detect() else {
            return;
        };
        let x = WORDS;
        let mut zz = [0; 10];
        expand(proof, &x, &mut zz);
        for (i, &word) in x.iter().enumerate() {
            assert_eq!([zz[2 * i], zz[2 * i + 1]], expand64_to128(word));
        }
    }
}
