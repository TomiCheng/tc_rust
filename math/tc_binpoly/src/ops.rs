use core::ptr;
use core::sync::atomic::{Ordering, compiler_fence};

/// Returns the number of `u64` limbs needed for an `n`-bit polynomial.
#[inline]
pub const fn size(n: usize) -> usize {
    (n + 63) >> 6
}

/// Computes polynomial addition over `GF(2)` (`z = x + y`).
pub fn add(x: &[u64], y: &[u64], z: &mut [u64]) {
    assert_eq!(x.len(), y.len(), "input lengths differ");
    assert_eq!(x.len(), z.len(), "output length differs");
    for ((z_i, &x_i), &y_i) in z.iter_mut().zip(x).zip(y) {
        *z_i = x_i ^ y_i;
    }
}

/// Adds `x` into `z` over `GF(2)` (`z += x`).
pub fn add_to(x: &[u64], z: &mut [u64]) {
    assert_eq!(x.len(), z.len(), "slice lengths differ");
    for (z_i, &x_i) in z.iter_mut().zip(x) {
        *z_i ^= x_i;
    }
}

/// Copies a polynomial value. This has no secret-wipe semantics.
pub fn copy(x: &[u64], z: &mut [u64]) {
    assert_eq!(x.len(), z.len(), "slice lengths differ");
    z.copy_from_slice(x);
}

/// Sets every limb to zero as an ordinary value-level operation.
#[inline]
pub fn zero(z: &mut [u64]) {
    z.fill(0);
}

/// Sets a non-empty limb slice to the polynomial one.
pub fn one(z: &mut [u64]) {
    let (low, rest) = z.split_first_mut().expect("one requires a non-empty slice");
    *low = 1;
    rest.fill(0);
}

/// Actively erases secret-bearing limbs with volatile writes.
///
/// This is deliberately separate from [`zero`]. The volatile stores and final
/// compiler fence prevent the compiler from deleting or moving the wipe across
/// the fence. They do not flush caches or provide a hardware memory barrier.
pub fn clear(z: &mut [u64]) {
    for word in z {
        // SAFETY: `word` is a valid, uniquely borrowed `u64` for this loop
        // iteration. Volatility changes optimization semantics, not validity.
        unsafe { ptr::write_volatile(word, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Constant-time equality test returning `u64::MAX` for equal and `0` otherwise.
pub fn equal_to(x: &[u64], y: &[u64]) -> u64 {
    assert_eq!(x.len(), y.len(), "slice lengths differ");
    let mut diff = 0_u64;
    for (&x_i, &y_i) in x.iter().zip(y) {
        diff |= x_i ^ y_i;
    }
    is_zero_mask(diff)
}

/// Constant-time test for polynomial one, returned as a `u64` mask.
pub fn equal_to_one(x: &[u64]) -> u64 {
    let Some((&low, rest)) = x.split_first() else {
        return 0;
    };
    let mut diff = low ^ 1;
    for &word in rest {
        diff |= word;
    }
    is_zero_mask(diff)
}

/// Constant-time test for polynomial zero, returned as a `u64` mask.
pub fn equal_to_zero(x: &[u64]) -> u64 {
    let mut diff = 0_u64;
    for &word in x {
        diff |= word;
    }
    is_zero_mask(diff)
}

/// Returns the variable-time bit length (degree plus one), or zero for zero.
pub fn bit_length_var(x: &[u64]) -> usize {
    for (index, &word) in x.iter().enumerate().rev() {
        if word != 0 {
            return (index + 1) * 64 - word.leading_zeros() as usize;
        }
    }
    0
}

#[inline]
fn is_zero_mask(value: u64) -> u64 {
    let nonzero = (value | value.wrapping_neg()) >> 63;
    nonzero.wrapping_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_matches_bc_formula() {
        assert_eq!(size(0), 0);
        assert_eq!(size(1), 1);
        assert_eq!(size(64), 1);
        assert_eq!(size(65), 2);
    }

    #[test]
    fn reduction_independent_operations_work() {
        let x = [1, 2, 3];
        let y = [3, 2, 1];
        let mut z = [0; 3];
        add(&x, &y, &mut z);
        assert_eq!(z, [2, 0, 2]);
        add_to(&x, &mut z);
        assert_eq!(z, y);
        copy(&x, &mut z);
        assert_eq!(z, x);
        one(&mut z);
        assert_eq!(z, [1, 0, 0]);
        zero(&mut z);
        assert_eq!(z, [0; 3]);
    }

    #[test]
    fn equality_helpers_return_masks() {
        assert_eq!(equal_to(&[1, 2], &[1, 2]), u64::MAX);
        assert_eq!(equal_to(&[1, 2], &[1, 3]), 0);
        assert_eq!(equal_to_one(&[1, 0]), u64::MAX);
        assert_eq!(equal_to_one(&[1, 1]), 0);
        assert_eq!(equal_to_zero(&[0, 0]), u64::MAX);
        assert_eq!(equal_to_zero(&[0, 1]), 0);
    }

    #[test]
    fn clear_writes_zeroes() {
        let mut secret = [u64::MAX, 7, 9];
        clear(&mut secret);
        assert_eq!(secret, [0; 3]);
    }

    #[test]
    fn bit_length_scans_little_endian_limbs() {
        assert_eq!(bit_length_var(&[0, 0]), 0);
        assert_eq!(bit_length_var(&[1, 0]), 1);
        assert_eq!(bit_length_var(&[0, 1]), 65);
        assert_eq!(bit_length_var(&[0, 1_u64 << 63]), 128);
    }
}
