//! 以拒絕取樣產生小於上界的隨機值。

use rand_core::{Rng, TryRng};

use crate::{
    BigUint, IsProbablePrime, NextProbablePrime, ProbablePrime, RandomBits, RandomBitsError,
    RandomMod,
};
use crate::{Limb, NonZero, PaddedBigUint, Word};

impl PaddedBigUint {
    /// 變動時間：只能用於公開的上界。均勻取樣 `[0, upper)`，結果寬度等於 `upper`。
    ///
    /// 走拒絕取樣，所以重試次數隨機；上界是公開的，取樣本身不洩漏結果。
    /// 也可透過 [`crate::RandomMod`] 使用相同的取樣契約。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::{NonZero, PaddedBigUint};
    ///
    /// // 僅用固定輸出示範呼叫；實際使用時傳入適合用途的 RNG。
    /// # struct ExampleRng;
    /// # impl tc_bigint::rand_core::TryRng for ExampleRng {
    /// #     type Error = core::convert::Infallible;
    /// #     fn try_next_u32(&mut self) -> Result<u32, Self::Error> { Ok(7) }
    /// #     fn try_next_u64(&mut self) -> Result<u64, Self::Error> { Ok(7) }
    /// #     fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
    /// #         out.fill(7); Ok(())
    /// #     }
    /// # }
    /// let mut rng = ExampleRng;
    /// let upper = NonZero::new(PaddedBigUint::from_be_bytes(&[101], 3).unwrap()).unwrap();
    /// let sample = PaddedBigUint::try_random_mod_vartime(&mut rng, &upper).unwrap();
    /// assert!(sample < *upper);
    /// assert_eq!(sample.len(), 3);
    /// ```
    pub fn try_random_mod_vartime<R: TryRng + ?Sized>(
        rng: &mut R,
        upper: &NonZero<Self>,
    ) -> Result<Self, R::Error> {
        let width = upper.len();
        let bit_length = upper.bit_len();
        loop {
            let candidate = Self::sample_bits(rng, bit_length, width)?;
            if candidate < **upper {
                return Ok(candidate);
            }
        }
    }

    /// 變動時間：只能用於公開的上界。無誤差 RNG 版本的 [`Self::try_random_mod_vartime`]。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::{NonZero, PaddedBigUint};
    ///
    /// // 僅用固定輸出示範呼叫；實際使用時傳入適合用途的 RNG。
    /// # struct ExampleRng;
    /// # impl tc_bigint::rand_core::TryRng for ExampleRng {
    /// #     type Error = core::convert::Infallible;
    /// #     fn try_next_u32(&mut self) -> Result<u32, Self::Error> { Ok(7) }
    /// #     fn try_next_u64(&mut self) -> Result<u64, Self::Error> { Ok(7) }
    /// #     fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
    /// #         out.fill(7); Ok(())
    /// #     }
    /// # }
    /// let mut rng = ExampleRng;
    /// let upper = NonZero::new(PaddedBigUint::from_be_bytes(&[101], 3).unwrap()).unwrap();
    /// let sample = PaddedBigUint::random_mod_vartime(&mut rng, &upper);
    /// assert!(sample < *upper);
    /// assert_eq!(sample.len(), 3);
    /// ```
    pub fn random_mod_vartime<R: Rng + ?Sized>(rng: &mut R, upper: &NonZero<Self>) -> Self {
        match Self::try_random_mod_vartime(rng, upper) {
            Ok(value) => value,
            Err(error) => match error {},
        }
    }

    /// 取 `bit_length` 個隨機位元，放進 `width` 個 limb 寬的儲存。
    fn sample_bits<R: TryRng + ?Sized>(
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

/// 變動時間：只能用於公開的位元數與精度。寬度由精度參數決定。
///
/// # Examples
/// ```
/// use tc_bigint::{PaddedBigUint, RandomBits, limbs_for_bits};
/// fn sample<R: tc_bigint::rand_core::Rng + ?Sized>(rng: &mut R) {
///     let value = PaddedBigUint::random_bits(rng, 65);
///     assert_eq!(value.len(), limbs_for_bits(65));
/// }
/// ```
impl RandomBits for PaddedBigUint {
    fn try_random_bits<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        Self::try_random_bits_with_precision(rng, bit_length, bit_length)
    }
    fn try_random_bits_with_precision<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
        bits_precision: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        if bit_length > bits_precision {
            return Err(RandomBitsError::BitLengthTooLarge {
                bit_length,
                bits_precision,
            });
        }
        Self::sample_bits(
            rng,
            bit_length as usize,
            crate::limbs_for_bits(bits_precision as usize),
        )
        .map_err(RandomBitsError::RandCore)
    }
}
/// 變動時間：只能用於公開的上界。沿用具名方法，保留模數寬度。
impl RandomMod for PaddedBigUint {
    fn try_random_mod_vartime<R: TryRng + ?Sized>(
        rng: &mut R,
        modulus: &NonZero<Self>,
    ) -> Result<Self, R::Error> {
        PaddedBigUint::try_random_mod_vartime(rng, modulus)
    }
}
/// 變動時間：只能用於公開的位元數。委派既有質數生成，寬度由要求位元數決定。
/// 回傳的是可能質數，不是數學證明。
impl ProbablePrime for PaddedBigUint {
    fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self {
        super::ops::public_result(
            BigUint::probable_prime(rng, bit_length),
            crate::limbs_for_bits(bit_length as usize),
        )
    }
}
/// 變動時間：只能用於公開值。沿用 `BigUint` 的可能質數測試，通過不代表數學證明。
impl IsProbablePrime for PaddedBigUint {
    fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool {
        self.to_big_uint().is_probable_prime(certainty, rng)
    }
}
/// 變動時間：只能用於公開值。搜尋下一個可能質數，超出原寬度時回 `None`。
impl NextProbablePrime for PaddedBigUint {
    type Output = Option<Self>;
    fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Self::Output {
        Self::from_big_uint(&self.to_big_uint().next_probable_prime(rng), self.len()).ok()
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
