use super::interleave;
#[cfg(target_arch = "x86_64")]
use super::x86;
use crate::reduce::Reducer;
use alloc::vec;
#[cfg(target_arch = "x86_64")]
use tc_runtime::intrinsics::x86::Bmi2X64;
use tc_zeroize::Zeroize;

/// BC's `BinPolyMulBase.StackAllocCutoff`: products up to this many limbs stay on the stack.
const STACK_CUTOFF: usize = 128;

/// How the bits are spread for squaring, picked once at construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Squarer {
    Portable,
    #[cfg(target_arch = "x86_64")]
    Bmi2(Bmi2X64),
}

impl Squarer {
    /// BMI2 PDEP when the CPU has it in 64-bit mode, as BC does, the bit shuffle otherwise.
    pub(crate) fn new() -> Self {
        #[cfg(target_arch = "x86_64")]
        if let Some(proof) = Bmi2X64::detect() {
            return Self::Bmi2(proof);
        }
        Self::Portable
    }

    /// BC's `BinPolyMulBase.Square`: `z = x² mod f`. Squaring over GF(2) only spreads the
    /// bits of `x` to the even positions, so there is no product to compute.
    pub(crate) fn square(&self, reducer: &Reducer, x: &[u64], z: &mut [u64]) {
        self.square_n(reducer, x, 1, z);
    }

    /// BC's `BinPolyMulBase.SquareN`: `z = x^(2^count) mod f`, `count >= 1`, reusing one
    /// product buffer.
    pub(crate) fn square_n(&self, reducer: &Reducer, x: &[u64], count: usize, z: &mut [u64]) {
        debug_assert!(count >= 1);
        let ext = 2 * x.len();
        if ext <= STACK_CUTOFF {
            let mut tt = [0_u64; STACK_CUTOFF];
            self.square_n_with(reducer, x, count, &mut tt[..ext], z);
            tt.zeroize();
        } else {
            let mut tt = vec![0_u64; ext];
            self.square_n_with(reducer, x, count, &mut tt, z);
            tt[..].zeroize();
        }
    }

    fn square_n_with(
        &self,
        reducer: &Reducer,
        x: &[u64],
        count: usize,
        tt: &mut [u64],
        z: &mut [u64],
    ) {
        self.expand(x, tt);
        reducer.reduce(tt, z);
        for _ in 1..count {
            self.expand(z, tt);
            reducer.reduce(tt, z);
        }
    }

    fn expand(&self, x: &[u64], tt: &mut [u64]) {
        match *self {
            Self::Portable => interleave::expand(x, tt),
            #[cfg(target_arch = "x86_64")]
            Self::Bmi2(proof) => x86::expand(proof, x, tt),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Squarer;
    use crate::multiply::Multiplier;
    use crate::reduce::Reducer;

    fn squarers() -> alloc::vec::Vec<Squarer> {
        #[cfg_attr(not(target_arch = "x86_64"), allow(unused_mut))]
        let mut squarers = alloc::vec![Squarer::Portable];
        #[cfg(target_arch = "x86_64")]
        if let Some(proof) = tc_runtime::intrinsics::x86::Bmi2X64::detect() {
            squarers.push(Squarer::Bmi2(proof));
        }
        squarers
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

            let mut expected = alloc::vec![0; size];
            Multiplier::new(size).multiply(&reducer, &x, &x, &mut expected);
            for squarer in squarers() {
                let mut z = alloc::vec![0; size];
                squarer.square(&reducer, &x, &mut z);
                assert_eq!(z, expected, "n = {n}, {squarer:?}");
            }
        }
    }

    #[test]
    fn squaring_n_times_is_squaring_once_n_times() {
        let reducer = Reducer::pentanomial(163, 3, 6, 7);
        let x = [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210, 0x7_FFFF_FFFF];
        for squarer in squarers() {
            let mut expected = x;
            for count in 1..=5 {
                let previous = expected;
                squarer.square(&reducer, &previous, &mut expected);
                let mut z = [0; 3];
                squarer.square_n(&reducer, &x, count, &mut z);
                assert_eq!(z, expected, "count = {count}, {squarer:?}");
            }
        }
    }
}
