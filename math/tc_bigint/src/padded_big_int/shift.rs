//! 私有定長位移核心；位移量與寬度是公開資訊。
use crate::{Limb, PaddedBigInt, Word};

impl PaddedBigInt {
    /// CT：左移並截斷高位，任意位移量都有原寬結果，超寬回零。
    pub(super) fn shl_core(&self, shift: usize) -> Self {
        let width = self.len();
        let bits = Word::BITS as usize;
        let limb_shift = shift / bits;
        let bit_shift = shift % bits;
        let mut out = Self::zero_with_limbs(width);
        for index in 0..width {
            let word = match index.checked_sub(limb_shift) {
                Some(source) => {
                    let low = self.limbs[source].to_word() << bit_shift;
                    let carried = if bit_shift == 0 || source == 0 {
                        0
                    } else {
                        self.limbs[source - 1].to_word() >> (bits - bit_shift)
                    };
                    low | carried
                }
                None => 0,
            };
            out.limbs[index] = Limb::new(word);
        }
        out
    }

    /// CT：算術右移，補入原符號位；任意位移量都有原寬結果。
    pub(super) fn shr_core(&self, shift: usize) -> Self {
        let width = self.len();
        let bits = Word::BITS as usize;
        let limb_shift = shift / bits;
        let bit_shift = shift % bits;
        let extension = self.sign_extension();
        let mut out = Self::zero_with_limbs(width);
        for index in 0..width {
            let word = match index.checked_add(limb_shift) {
                Some(source) if source < width => {
                    let low = self.limbs[source].to_word() >> bit_shift;
                    let high = self
                        .limbs
                        .get(source + 1)
                        .map_or(extension, |limb| limb.to_word());
                    low | if bit_shift == 0 {
                        0
                    } else {
                        high << (bits - bit_shift)
                    }
                }
                _ => extension,
            };
            out.limbs[index] = Limb::new(word);
        }
        out
    }
}
