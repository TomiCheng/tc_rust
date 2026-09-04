//! Shared operations over big-endian magnitude words.

use crate::limb::{WideWord, Word};

/// Adds `y` to `x` in place with their least-significant words aligned.
///
/// `x` must be at least as long as `y` and must already include enough leading
/// space to absorb the final carry.
pub(crate) fn add_in_place(x: &mut [Word], y: &[Word]) {
    debug_assert!(x.len() >= y.len(), "add_in_place 需要 x.len() >= y.len()");

    let mut carry: WideWord = 0;
    let mut xi = x.len();

    for &yw in y.iter().rev() {
        xi -= 1;
        carry += x[xi] as WideWord + yw as WideWord;
        x[xi] = carry as Word;
        carry >>= Word::BITS;
    }

    while carry != 0 && xi > 0 {
        xi -= 1;
        carry += x[xi] as WideWord;
        x[xi] = carry as Word;
        carry >>= Word::BITS;
    }

    debug_assert!(carry == 0, "add_in_place 溢位：x 未預留足夠長度");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_in_place_basic() {
        let mut x = [0, 5];
        add_in_place(&mut x, &[3]);
        assert_eq!(x, [0, 8]);

        let mut x = [0, Word::MAX];
        add_in_place(&mut x, &[1]);
        assert_eq!(x, [1, 0]);

        let mut x = [0, Word::MAX, Word::MAX];
        add_in_place(&mut x, &[1]);
        assert_eq!(x, [1, 0, 0]);

        let mut x = [0, 0x1000_0000];
        add_in_place(&mut x, &[0, 0x2000_0000]);
        assert_eq!(x, [0, 0x3000_0000]);
    }
}
