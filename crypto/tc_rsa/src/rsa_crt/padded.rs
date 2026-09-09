//! 寬度由金鑰決定的 RSA 中國剩餘定理核心。

use rand_core::CryptoRng;
use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
use tc_bigint::{NonZero, Odd, PaddedBigUint, limbs_for_bits};
use tc_cipher::{AsymmetricBlockCipher, CipherDirection};
use tc_constant_time::ConstantTimeEq;

use crate::rsa_core::padded;
use crate::rsa_crt::validate;
use crate::{Rsa, RsaCrt, RsaCrtInit, RsaError, RsaPrivateCrtKeyParams};

/// 寬度在 [`RsaCrtInit::init`] 時由金鑰決定的 CRT 核心。
///
/// 半寬 `h` 取自模數位元數，全寬固定是 `2h`，所以「全寬是半寬兩倍」這個
/// 不變式由建構方式保證，不需要 [`crate::FixedRsaCrtCoreEngine`] 那樣的
/// 編譯期斷言。質因數放不進半寬時 [`RsaCrtInit::init`] 會回錯誤。
///
/// 金鑰材料離開作用域時自動清除。
#[derive(Default)]
pub struct PaddedRsaCrtCoreEngine {
    inner: Option<Inner>,
}

/// 初始化後才存在的狀態。
struct Inner {
    modulus: Odd<PaddedBigUint>,
    modulus_minus_one: PaddedBigUint,
    public_exponent: PaddedBigUint,
    q: PaddedBigUint,
    dp: PaddedBigUint,
    dq: PaddedBigUint,
    params_p: PaddedMontyParams,
    params_q: PaddedMontyParams,
    params_n: PaddedMontyParams,
    q_inv_form: PaddedMontyForm,
    bit_size: usize,
    direction: CipherDirection,
}

impl Inner {
    fn new<K: RsaPrivateCrtKeyParams + ?Sized>(
        direction: CipherDirection,
        key: &K,
    ) -> Result<Self, RsaError> {
        let bit_size = validate(key)?;
        // 半寬取上界，全寬固定是兩倍，模數因此一定裝得下。
        let half = limbs_for_bits(bit_size).div_ceil(2);
        let full = 2 * half;

        let modulus = padded(key.modulus(), full, RsaError::InvalidModulus)?;
        let public_exponent = padded(key.public_exponent(), full, RsaError::InvalidExponent)?;
        let p = padded(key.p(), half, RsaError::InvalidP)?;
        let q = padded(key.q(), half, RsaError::InvalidQ)?;
        let dp = padded(key.dp(), half, RsaError::InvalidDp)?;
        let dq = padded(key.dq(), half, RsaError::InvalidDq)?;
        let q_inv = padded(key.q_inv(), half, RsaError::InvalidQInv)?;

        let one = padded(&[1], full, RsaError::InvalidModulus)?;
        let (modulus_minus_one, borrow) = modulus.sub(&one);
        if borrow {
            return Err(RsaError::InvalidModulus);
        }

        let params_p = PaddedMontyParams::new(Odd::new(p).ok_or(RsaError::InvalidP)?);
        let params_q = PaddedMontyParams::new(Odd::new(q.clone()).ok_or(RsaError::InvalidQ)?);
        let modulus = Odd::new(modulus).ok_or(RsaError::EvenModulus)?;
        let params_n = PaddedMontyParams::new(modulus.clone());
        // 參數是 `Arc` owned 的，所以 form 可以直接存起來，不會有自我參照。
        let q_inv_form = PaddedMontyForm::new_ct(&q_inv, params_p.clone());

        Ok(Self {
            modulus,
            modulus_minus_one,
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

/// 所有金鑰材料都存在 [`PaddedBigUint`] 裡，離開作用域時自動清除。
impl tc_bigint::ZeroizeOnDrop for PaddedRsaCrtCoreEngine {}

impl PaddedRsaCrtCoreEngine {
    /// 取得初始化後的狀態，未初始化時回 [`RsaError::NotInitialized`]。
    fn inner(&self) -> Result<&Inner, RsaError> {
        self.inner.as_ref().ok_or(RsaError::NotInitialized)
    }
}

impl<K: RsaPrivateCrtKeyParams + ?Sized> RsaCrtInit<K> for PaddedRsaCrtCoreEngine {
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, parameters: &K) -> Result<(), Self::Error> {
        // 先建好再寫回，失敗時引擎維持原狀，不會留下半初始化的金鑰。
        let inner = Inner::new(direction, parameters)?;
        self.inner = Some(inner);
        Ok(())
    }
}

impl AsymmetricBlockCipher for PaddedRsaCrtCoreEngine {
    type Error = RsaError;

    fn input_block_size(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, |inner| match inner.direction {
                CipherDirection::Encrypt => inner.bit_size.saturating_sub(1) / 8,
                CipherDirection::Decrypt => inner.bit_size.div_ceil(8),
            })
    }

    fn output_block_size(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, |inner| match inner.direction {
                CipherDirection::Encrypt => inner.bit_size.div_ceil(8),
                CipherDirection::Decrypt => inner.bit_size.saturating_sub(1) / 8,
            })
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let value = self.convert_input(input)?;
        let result = self.process_int(&value)?;
        self.convert_output(&result, output)
    }
}

impl Rsa for PaddedRsaCrtCoreEngine {
    type RsaBigInt = PaddedBigUint;

    fn convert_input(&self, input: &[u8]) -> Result<Self::RsaBigInt, Self::Error> {
        let inner = self.inner()?;
        let width = inner.params_n.len();
        let input = padded(input, width, RsaError::InputTooLarge)?;

        // 0、1 與 n-1 的模冪結果等於自身，帶不出資訊；一律當成無效輸入擋掉。
        if input <= padded(&[1], width, RsaError::InputTooSmall)? {
            return Err(RsaError::InputTooSmall);
        }
        if input >= inner.modulus_minus_one {
            return Err(RsaError::InputTooLarge);
        }
        Ok(input)
    }

    /// 不盲化的 CRT 運算。
    ///
    /// 只做中國剩餘定理與 Lenstra 故障檢查，**不含盲化**。私鑰暴露在遠端計時
    /// 之下時請改用 [`RsaCrt::process_int_blinded`]。
    fn process_int(&mut self, input: &Self::RsaBigInt) -> Result<Self::RsaBigInt, Self::Error> {
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
            .write_be_bytes(&mut output[output_len - result_len..output_len])
            .map_err(|_| RsaError::OutputTooShort)?;
        Ok(output_len)
    }
}

impl RsaCrt for PaddedRsaCrtCoreEngine {
    fn process_int_blinded<R: CryptoRng + ?Sized>(
        &mut self,
        input: &Self::RsaBigInt,
        rng: &mut R,
    ) -> Result<Self::RsaBigInt, Self::Error> {
        self.inner()?.process_blinded(input, rng)
    }
}

impl Inner {
    /// 以中國剩餘定理計算 `input^d mod n`，並用公開指數驗算結果。
    fn process_crt(&self, input: &PaddedBigUint) -> Result<PaddedBigUint, RsaError> {
        // `new_ct` 吃得下比模數寬的輸入，所以全寬的 input 可以直接進半寬的域。
        let m_p_form = PaddedMontyForm::new_ct(input, self.params_p.clone()).pow_ct(&self.dp);
        let m_q_form = PaddedMontyForm::new_ct(input, self.params_q.clone()).pow_ct(&self.dq);
        let m_q = m_q_form.retrieve();
        let m_q_in_p = PaddedMontyForm::new_ct(&m_q, self.params_p.clone());
        let h = ((m_p_form - m_q_in_p) * self.q_inv_form.clone()).retrieve();
        let (low, high) = h.mul_wide(&self.q);

        // h < p 且 m_q < q，所以 h*q + m_q <= (p-1)*q + (q-1) = n-1，必定裝得進全寬。
        let widened = m_q
            .resize(self.params_n.len())
            .map_err(|_| RsaError::FaultyDecryptionOrSigning)?;
        let (result, carry) = PaddedBigUint::concat(&low, &high).add(&widened);
        if carry {
            return Err(RsaError::FaultyDecryptionOrSigning);
        }

        // 驗算比對的是公開的密文，指數也是公開的 `e`，整條都用變動時間版本。
        let check = PaddedMontyForm::new(&result, self.params_n.clone())
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
        input: &PaddedBigUint,
        rng: &mut R,
    ) -> Result<PaddedBigUint, RsaError> {
        let upper =
            NonZero::new_padded(self.modulus_minus_one.clone()).ok_or(RsaError::InvalidModulus)?;
        let one = padded(&[1], self.params_n.len(), RsaError::InvalidModulus)?;
        // `PaddedBigUint` 是 ZeroizeOnDrop，`r` 與其反元素離開作用域就會被清除。
        let (r, _) = PaddedBigUint::random_mod_vartime(rng, &upper).add(&one);

        // `r` 是秘密，所以進域走固定排程；只有指數 `e` 是公開的。
        let blind = PaddedMontyForm::new_ct(&r, self.params_n.clone()).pow(&self.public_exponent);
        // 秘密的 r 走固定步數的 safegcd，不用變動時間的 Euclid。
        let inverse = r
            .mod_odd_inverse_ct(&self.modulus)
            .ok_or(RsaError::FaultyDecryptionOrSigning)?;
        let unblind = PaddedMontyForm::new_ct(&inverse, self.params_n.clone());

        let input_form = PaddedMontyForm::new_ct(input, self.params_n.clone());
        let blinded_input = (blind * input_form).retrieve();
        let blinded_result = self.process_crt(&blinded_input)?;
        let result_form = PaddedMontyForm::new_ct(&blinded_result, self.params_n.clone());

        Ok((unblind * result_form).retrieve())
    }
}
