//! 固定寬度、無 alloc 的 CRT 私鑰核心。

use rand_core::CryptoRng;
use tc_bigint::modular::{FixedMontyForm, FixedMontyParams};
use tc_bigint::{FixedBigUint, NonZero, Odd, RandomMod};
use tc_cipher::CipherDirection;
use tc_constant_time::ConstantTimeEq;

use crate::rsa_crt::validate;
use crate::{Rsa, RsaCrt, RsaCrtInit, RsaError, RsaPrivateCrtKeyParams};

/// 以中國剩餘定理加速的固定寬度私鑰核心。
///
/// `N` 是模數的 limb 數，`H` 是質因數的 limb 數，兩者必須滿足 `N == 2 * H`；
/// 建構時會擋下不符的實例化。
///
/// 每次私鑰運算都重新取樣盲化因子，並以公開指數做 Lenstra 故障檢查——前者降低
/// 遠端計時的可觀測性，後者避免單邊計算出錯就洩漏因數分解，兩者防護的問題不同，
/// 不能互相取代。
/// 以 [`Default`] 建立的引擎尚未持有金鑰，運算方法會回
/// [`RsaError::NotInitialized`]，區塊大小則為 `0`。
#[derive(Clone, Copy, Default)]
pub struct FixedRsaCrtCoreEngine<const N: usize, const H: usize> {
    inner: Option<Inner<N, H>>,
}

/// 初始化後才存在的狀態。
#[derive(Clone, Copy)]
struct Inner<const N: usize, const H: usize> {
    modulus: FixedBigUint<N>,
    public_exponent: FixedBigUint<N>,
    q: FixedBigUint<H>,
    dp: FixedBigUint<H>,
    dq: FixedBigUint<H>,
    params_p: FixedMontyParams<H>,
    params_q: FixedMontyParams<H>,
    params_n: FixedMontyParams<N>,
    q_inv_form: FixedMontyForm<H>,
    bit_size: usize,
    direction: CipherDirection,
}

impl<const N: usize, const H: usize> Inner<N, H> {
    /// 全寬必須剛好是半寬的兩倍；不符時在建構期就會 panic。
    const WIDTH_CHECK: () = assert!(
        N == 2 * H,
        "RSA CRT full width must be twice the half width"
    );

    fn new<K: RsaPrivateCrtKeyParams + ?Sized>(
        direction: CipherDirection,
        key: &K,
    ) -> Result<Self, RsaError> {
        let () = Self::WIDTH_CHECK;

        let bit_size = validate(key)?;
        let modulus = fixed(key.modulus(), RsaError::InvalidModulus)?;
        let public_exponent = fixed(key.public_exponent(), RsaError::InvalidExponent)?;
        let p = fixed(key.p(), RsaError::InvalidP)?;
        let q = fixed(key.q(), RsaError::InvalidQ)?;
        let dp = fixed(key.dp(), RsaError::InvalidDp)?;
        let dq = fixed(key.dq(), RsaError::InvalidDq)?;
        let q_inv = fixed(key.q_inv(), RsaError::InvalidQInv)?;

        let params_p = FixedMontyParams::new(Odd::new(p).ok_or(RsaError::InvalidP)?);
        let params_q = FixedMontyParams::new(Odd::new(q).ok_or(RsaError::InvalidQ)?);
        let params_n = FixedMontyParams::new(Odd::new(modulus).ok_or(RsaError::EvenModulus)?);
        let q_inv_form = FixedMontyForm::new_ct(&q_inv, params_p);

        Ok(Self {
            modulus,
            public_exponent,
            q,
            dp,
            dq,
            params_p,
            params_q,
            params_n,
            q_inv_form,
            bit_size,
            direction,
        })
    }
}

impl<const N: usize, const H: usize> FixedRsaCrtCoreEngine<N, H> {
    /// 取得初始化後的狀態，未初始化時回 [`RsaError::NotInitialized`]。
    fn inner(&self) -> Result<&Inner<N, H>, RsaError> {
        self.inner.as_ref().ok_or(RsaError::NotInitialized)
    }
}

impl<K: RsaPrivateCrtKeyParams + ?Sized, const N: usize, const H: usize> RsaCrtInit<K>
    for FixedRsaCrtCoreEngine<N, H>
{
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, parameters: &K) -> Result<(), Self::Error> {
        // 先建好再寫回，失敗時引擎維持原狀，不會留下半初始化的金鑰。
        let inner = Inner::new(direction, parameters)?;
        self.inner = Some(inner);
        Ok(())
    }
}

impl<const N: usize, const H: usize> Rsa for FixedRsaCrtCoreEngine<N, H> {
    type RsaBigInt = FixedBigUint<N>;
    type Error = RsaError;

    fn input_block_size(&self) -> usize {
        self.inner.map_or(0, |inner| match inner.direction {
            CipherDirection::Encrypt => inner.bit_size.saturating_sub(1) / 8,
            CipherDirection::Decrypt => inner.bit_size.div_ceil(8),
        })
    }

    fn output_block_size(&self) -> usize {
        self.inner.map_or(0, |inner| match inner.direction {
            CipherDirection::Encrypt => inner.bit_size.div_ceil(8),
            CipherDirection::Decrypt => inner.bit_size.saturating_sub(1) / 8,
        })
    }

    fn convert_input(&self, input: &[u8]) -> Result<Self::RsaBigInt, Self::Error> {
        let inner = self.inner()?;
        let input = fixed(input, RsaError::InputTooLarge)?;
        // 0、1 與 n-1 的模冪結果等於自身，帶不出資訊；一律當成無效輸入擋掉。
        if input <= FixedBigUint::from(1_u8) {
            return Err(RsaError::InputTooSmall);
        }
        if input >= inner.modulus - FixedBigUint::from(1_u8) {
            return Err(RsaError::InputTooLarge);
        }
        Ok(input)
    }

    /// 不盲化的 CRT 運算。
    ///
    /// 只做中國剩餘定理與 Lenstra 故障檢查，**不含盲化**。私鑰暴露在遠端計時
    /// 之下時請改用 [`RsaCrt::process_block_blinded`]。
    fn process_block(&mut self, input: &Self::RsaBigInt) -> Result<Self::RsaBigInt, Self::Error> {
        self.inner()?.process_crt(input)
    }

    fn convert_output(
        &self,
        result: &Self::RsaBigInt,
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let inner = self.inner()?;
        let result_len = result.byte_length_unsigned();
        // 加密輸出固定補到模數長度；解密輸出用最短表示法，與 Bouncy Castle 一致。
        let output_len = match inner.direction {
            CipherDirection::Encrypt => inner.bit_size.div_ceil(8),
            CipherDirection::Decrypt => result_len,
        };
        if output.len() < output_len || result_len > output_len {
            return Err(RsaError::OutputTooShort);
        }

        output[..output_len].fill(0);
        result
            .write_unsigned_be_bytes(&mut output[output_len - result_len..output_len])
            .map_err(|_| RsaError::OutputTooShort)?;
        Ok(output_len)
    }
}

impl<const N: usize, const H: usize> RsaCrt for FixedRsaCrtCoreEngine<N, H> {
    fn process_block_blinded<R: CryptoRng + ?Sized>(
        &mut self,
        input: &Self::RsaBigInt,
        rng: &mut R,
    ) -> Result<Self::RsaBigInt, Self::Error> {
        self.inner()?.process_blinded(input, rng)
    }
}

impl<const N: usize, const H: usize> Inner<N, H> {
    /// 以中國剩餘定理計算 `input^d mod n`，並用公開指數驗算結果。
    fn process_crt(&self, input: &FixedBigUint<N>) -> Result<FixedBigUint<N>, RsaError> {
        let m_p_form = FixedMontyForm::new_ct_wide(input, self.params_p).pow_ct(&self.dp);
        let m_q_form = FixedMontyForm::new_ct_wide(input, self.params_q).pow_ct(&self.dq);
        let m_q = m_q_form.retrieve();
        let m_q_in_p = FixedMontyForm::new_ct(&m_q, self.params_p);
        let h = ((m_p_form - m_q_in_p) * self.q_inv_form).retrieve();
        let (low, high) = h.mul_wide(&self.q);

        // h < p 且 m_q < q，所以 h*q + m_q <= (p-1)*q + (q-1) = n-1，必定裝得進 N。
        let result = FixedBigUint::<N>::concat(&low, &high) + FixedBigUint::<N>::widen_from(&m_q);
        let check = FixedMontyForm::new(&result, self.params_n)
            .pow(&self.public_exponent)
            .retrieve();

        // 單邊算錯就能從 gcd(result^e - input, n) 分解 n，所以結果必須先驗算過才交出去。
        // 判定只決定是否回傳，不會揭露未通過驗證的私密中間值。
        if check.ct_eq(input).unwrap_u8() != 1 {
            return Err(RsaError::FaultyDecryptionOrSigning);
        }
        Ok(result)
    }

    /// 以每次重新取樣的盲化因子包住 CRT 運算。
    ///
    /// 取 `r` 均勻分布於 `[1, n-1]`，先乘上 `r^e`、算完再乘 `r^-1`，讓可觀測的
    /// 中間值與真正的輸入無關。
    fn process_blinded<R: CryptoRng + ?Sized>(
        &self,
        input: &FixedBigUint<N>,
        rng: &mut R,
    ) -> Result<FixedBigUint<N>, RsaError> {
        let upper = NonZero::new(self.modulus - FixedBigUint::from(1_u8))
            .ok_or(RsaError::InvalidModulus)?;
        let r = FixedBigUint::random_mod_vartime(rng, &upper) + FixedBigUint::from(1_u8);

        let blind = FixedMontyForm::new(&r, self.params_n).pow(&self.public_exponent);
        // FixedMontyForm::invert 走變動時間 Euclid；秘密 r 改用固定步數的 safegcd。
        let modulus = Odd::new(self.modulus).ok_or(RsaError::InvalidModulus)?;
        let inverse = r
            .mod_odd_inverse_ct(&modulus)
            .ok_or(RsaError::FaultyDecryptionOrSigning)?;
        let unblind = FixedMontyForm::new_ct(&inverse, self.params_n);

        let input_form = FixedMontyForm::new(input, self.params_n);
        let blinded_input = (blind * input_form).retrieve();
        let blinded_result = self.process_crt(&blinded_input)?;
        let result_form = FixedMontyForm::new_ct(&blinded_result, self.params_n);

        Ok((unblind * result_form).retrieve())
    }
}

/// 把大端序位元組轉成固定寬度整數；放不進目標寬度時回傳指定的錯誤。
fn fixed<const W: usize>(value: &[u8], error: RsaError) -> Result<FixedBigUint<W>, RsaError> {
    FixedBigUint::from_be_bytes(value).map_err(|_| error)
}
