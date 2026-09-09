//! 以拒絕取樣產生小於上界的隨機值。

use rand_core::{Rng, TryRng};

use crate::{Limb, NonZero, PaddedBigUint, Word};

impl PaddedBigUint {
    /// 變動時間：只能用於公開的上界。均勻取樣 `[0, upper)`，結果寬度等於 `upper`。
    ///
    /// 走拒絕取樣，所以重試次數隨機；上界是公開的，取樣本身不洩漏結果。
    /// 本型別不實作 [`crate::traits::RandomMod`]：那個 trait 要求 `Zero`，
    /// 而 `Zero` 要求 `Add<Self>`，本型別刻意不提供運算子。
    pub fn try_random_mod_vartime<R: TryRng + ?Sized>(
        rng: &mut R,
        upper: &NonZero<Self>,
    ) -> Result<Self, R::Error> {
        let width = upper.len();
        let bit_length = upper.bit_len();
        loop {
            let candidate = Self::try_random_bits(rng, bit_length, width)?;
            if candidate < **upper {
                return Ok(candidate);
            }
        }
    }

    /// 變動時間：只能用於公開的上界。無誤差 RNG 版本的 [`Self::try_random_mod_vartime`]。
    pub fn random_mod_vartime<R: Rng + ?Sized>(rng: &mut R, upper: &NonZero<Self>) -> Self {
        match Self::try_random_mod_vartime(rng, upper) {
            Ok(value) => value,
            Err(error) => match error {},
        }
    }

    /// 取 `bit_length` 個隨機位元，放進 `width` 個 limb 寬的儲存。
    fn try_random_bits<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: usize,
        width: usize,
    ) -> Result<Self, R::Error> {
        let bits = Word::BITS as usize;
        let mut out = Self::zero_with_limbs(width);
        let filled = bit_length.div_ceil(bits).min(width);

        for index in 0..filled {
            out.as_limbs_mut()[index] = Limb::new(try_random_word(rng)?);
        }

        // 把最高的那個 limb 截到上界的位元數，減少拒絕次數。
        let top_bits = bit_length % bits;
        if top_bits != 0 && filled != 0 {
            let mask = Word::MAX >> (bits - top_bits);
            let word = out.as_limbs()[filled - 1].to_word() & mask;
            out.as_limbs_mut()[filled - 1] = Limb::new(word);
        }

        Ok(out)
    }
}

/// 取一個隨機字，寬度隨目標平台。
fn try_random_word<R: TryRng + ?Sized>(rng: &mut R) -> Result<Word, R::Error> {
    #[cfg(target_pointer_width = "64")]
    {
        let mut bytes = [0_u8; 8];
        rng.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    #[cfg(not(target_pointer_width = "64"))]
    {
        let mut bytes = [0_u8; 4];
        rng.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
}
