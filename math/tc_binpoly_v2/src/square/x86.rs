// The intrinsic is unsafe before Rust 1.87 and safe inside these functions after it.
#![allow(unused_unsafe)]

use core::arch::x86_64::_pdep_u64;
use tc_runtime::intrinsics::x86::Bmi2X64;

/// BC's `Interleave.Expand64To128` on its BMI2 path: one PDEP per half word. Constant time
/// where PDEP is; AMD before Zen 3 runs it in microcode, slowly.
pub(super) fn expand(_proof: Bmi2X64, x: &[u64], zz: &mut [u64]) {
    // SAFETY: the proof shows the CPU has BMI2 in 64-bit mode.
    unsafe { expand_pdep(x, zz) }
}

#[target_feature(enable = "bmi2")]
unsafe fn expand_pdep(x: &[u64], zz: &mut [u64]) {
    const M64: u64 = 0x5555_5555_5555_5555;
    for (i, &word) in x.iter().enumerate() {
        unsafe {
            zz[2 * i] = _pdep_u64(word, M64);
            zz[2 * i + 1] = _pdep_u64(word >> 32, M64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::interleave::spread;
    use super::expand;
    use tc_runtime::intrinsics::x86::Bmi2X64;

    #[test]
    fn expanding_moves_bit_i_to_bit_2i() {
        let Some(proof) = Bmi2X64::detect() else {
            return;
        };
        let x = [0, 1, u64::MAX, 0x8000_0000_0000_0001, 0x0123_4567_89AB_CDEF];
        let mut zz = [0; 10];
        expand(proof, &x, &mut zz);
        assert_eq!(zz.to_vec(), spread(&x));
    }
}
