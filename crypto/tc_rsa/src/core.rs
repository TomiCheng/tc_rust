//! RSA 核心運算與輸入輸出轉換。

use rand_core::CryptoRng;
use tc_bigint::modular::{FixedMontyForm, FixedMontyParams};
use tc_bigint::{BigUint, FixedBigUint, NonZero, Odd, RandomMod, Word};
use tc_cipher::CipherDirection;
use tc_constant_time::ConstantTimeEq;

use crate::{RsaError, RsaKey, RsaKeyParameters, RsaPrivateCrtKeyParameters};

const fn limbs(bits: usize) -> usize {
    bits / Word::BITS as usize
}

#[derive(Clone, Copy)]
struct StandardInner<const N: usize> {
    modulus: FixedBigUint<N>,
    exponent: FixedBigUint<N>,
    params_n: FixedMontyParams<N>,
    is_private: bool,
}

impl<const N: usize> StandardInner<N> {
    fn new(params: &RsaKeyParameters<'_>) -> Result<Self, RsaError> {
        let modulus = fixed(params.modulus(), RsaError::InvalidModulus)?;
        let exponent = fixed(
            params.exponent(),
            if params.is_private() {
                RsaError::InvalidPrivateExponent
            } else {
                RsaError::InvalidExponent
            },
        )?;
        let odd_modulus = Odd::new(modulus).ok_or(RsaError::EvenModulus)?;

        Ok(Self {
            modulus,
            exponent,
            params_n: FixedMontyParams::new(odd_modulus),
            is_private: params.is_private(),
        })
    }

    fn process(
        &self,
        input: &[u8],
        output: &mut [u8],
        direction: CipherDirection,
    ) -> Result<usize, RsaError> {
        let input = convert_input(input, &self.modulus)?;
        let result = if self.is_private {
            FixedMontyForm::new_ct(&input, self.params_n)
                .pow_ct(&self.exponent)
                .retrieve()
        } else {
            FixedMontyForm::new(&input, self.params_n)
                .pow(&self.exponent)
                .retrieve()
        };
        convert_output(&result, output, direction, self.modulus.bit_length())
    }
}

#[derive(Clone, Copy)]
// 金鑰桶刻意直接持有固定寬度資料，避免額外間接層；桶寬是公開資訊。
#[allow(clippy::large_enum_variant)]
enum StandardKey {
    Bits1024(StandardInner<{ limbs(1024) }>),
    Bits2048(StandardInner<{ limbs(2048) }>),
    Bits3072(StandardInner<{ limbs(3072) }>),
    Bits4096(StandardInner<{ limbs(4096) }>),
}

macro_rules! with_standard_inner {
    ($value:expr, $inner:ident => $body:expr) => {
        match $value {
            StandardKey::Bits1024($inner) => $body,
            StandardKey::Bits2048($inner) => $body,
            StandardKey::Bits3072($inner) => $body,
            StandardKey::Bits4096($inner) => $body,
        }
    };
}

impl StandardKey {
    fn new(params: &RsaKeyParameters<'_>) -> Result<Self, RsaError> {
        match bucket(params.modulus().bits())? {
            1024 => Ok(Self::Bits1024(StandardInner::new(params)?)),
            2048 => Ok(Self::Bits2048(StandardInner::new(params)?)),
            3072 => Ok(Self::Bits3072(StandardInner::new(params)?)),
            4096 => Ok(Self::Bits4096(StandardInner::new(params)?)),
            _ => unreachable!(),
        }
    }

    fn process(
        &self,
        input: &[u8],
        output: &mut [u8],
        direction: CipherDirection,
    ) -> Result<usize, RsaError> {
        with_standard_inner!(self, inner => inner.process(input, output, direction))
    }

    #[cfg(test)]
    fn bucket_bits(&self) -> usize {
        with_standard_inner!(self, inner => inner.modulus.byte_length() * 8)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CrtInner<const N: usize, const H: usize> {
    modulus: FixedBigUint<N>,
    public_exponent: FixedBigUint<N>,
    q: FixedBigUint<H>,
    dp: FixedBigUint<H>,
    dq: FixedBigUint<H>,
    params_p: FixedMontyParams<H>,
    params_q: FixedMontyParams<H>,
    params_n: FixedMontyParams<N>,
    q_inv_form: FixedMontyForm<H>,
}

impl<const N: usize, const H: usize> CrtInner<N, H> {
    fn new(params: &RsaPrivateCrtKeyParameters<'_>) -> Result<Self, RsaError> {
        assert!(
            N == 2 * H,
            "RSA CRT full width must be twice the half width"
        );

        let modulus = fixed(params.modulus(), RsaError::InvalidModulus)?;
        let public_exponent = fixed(params.public_exponent(), RsaError::InvalidExponent)?;
        let p = fixed(params.p(), RsaError::InvalidP)?;
        let q = fixed(params.q(), RsaError::InvalidQ)?;
        let dp = fixed(params.dp(), RsaError::InvalidDp)?;
        let dq = fixed(params.dq(), RsaError::InvalidDq)?;
        let q_inv = fixed(params.q_inv(), RsaError::InvalidQInv)?;
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
        })
    }

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

        // 故障判定只會決定是否公開回傳結果，不會揭露未通過驗證的私密中間值。
        if check.ct_eq(input).unwrap_u8() != 1 {
            return Err(RsaError::FaultyDecryptionOrSigning);
        }
        Ok(result)
    }

    fn process<R: CryptoRng + ?Sized>(
        &self,
        input: &[u8],
        output: &mut [u8],
        direction: CipherDirection,
        rng: &mut R,
    ) -> Result<usize, RsaError> {
        let input = convert_input(input, &self.modulus)?;
        let upper = NonZero::new(self.modulus - FixedBigUint::from(1_u8))
            .ok_or(RsaError::InvalidModulus)?;
        let r = FixedBigUint::random_mod_vartime(rng, &upper) + FixedBigUint::from(1_u8);

        let blind = FixedMontyForm::new(&r, self.params_n).pow(&self.public_exponent);
        // FixedMontyForm::invert 目前走變動時間 Euclid；秘密 r 改用公開的固定步 safegcd。
        let modulus = Odd::new(self.modulus).ok_or(RsaError::InvalidModulus)?;
        let inverse = r
            .mod_odd_inverse_ct(&modulus)
            .ok_or(RsaError::FaultyDecryptionOrSigning)?;
        let unblind = FixedMontyForm::new_ct(&inverse, self.params_n);
        let input_form = FixedMontyForm::new(&input, self.params_n);
        let blinded_input = (blind * input_form).retrieve();
        let blinded_result = self.process_crt(&blinded_input)?;
        let result_form = FixedMontyForm::new_ct(&blinded_result, self.params_n);
        let result = (unblind * result_form).retrieve();

        convert_output(&result, output, direction, self.modulus.bit_length())
    }
}

#[derive(Clone, Copy)]
// 工單指定 enum 只留在最外層，內層 CrtInner 保持單一泛型實作。
#[allow(clippy::large_enum_variant)]
pub(crate) enum RsaPrivateCrtKey {
    Bits1024(CrtInner<{ limbs(1024) }, { limbs(512) }>),
    Bits2048(CrtInner<{ limbs(2048) }, { limbs(1024) }>),
    Bits3072(CrtInner<{ limbs(3072) }, { limbs(1536) }>),
    Bits4096(CrtInner<{ limbs(4096) }, { limbs(2048) }>),
}

macro_rules! with_crt_inner {
    ($value:expr, $inner:ident => $body:expr) => {
        match $value {
            RsaPrivateCrtKey::Bits1024($inner) => $body,
            RsaPrivateCrtKey::Bits2048($inner) => $body,
            RsaPrivateCrtKey::Bits3072($inner) => $body,
            RsaPrivateCrtKey::Bits4096($inner) => $body,
        }
    };
}

impl RsaPrivateCrtKey {
    fn new_by_half_width(params: &RsaPrivateCrtKeyParameters<'_>) -> Result<Self, RsaError> {
        match params.p().bits().max(params.q().bits()) {
            0..=512 => Ok(Self::Bits1024(CrtInner::new(params)?)),
            513..=1024 => Ok(Self::Bits2048(CrtInner::new(params)?)),
            1025..=1536 => Ok(Self::Bits3072(CrtInner::new(params)?)),
            1537..=2048 => Ok(Self::Bits4096(CrtInner::new(params)?)),
            _ => Err(RsaError::InvalidModulus),
        }
    }

    fn process<R: CryptoRng + ?Sized>(
        &self,
        input: &[u8],
        output: &mut [u8],
        direction: CipherDirection,
        rng: &mut R,
    ) -> Result<usize, RsaError> {
        with_crt_inner!(self, inner => inner.process(input, output, direction, rng))
    }

    #[cfg(test)]
    fn bucket_bits(&self) -> usize {
        with_crt_inner!(self, inner => inner.modulus.byte_length() * 8)
    }
}

#[derive(Clone, Copy)]
// CRT 與非 CRT 金鑰大小不同是固定桶設計的預期結果。
#[allow(clippy::large_enum_variant)]
enum CoreKey {
    Standard(StandardKey),
    PrivateCrt(RsaPrivateCrtKey),
}

pub(crate) struct RsaCoreEngine {
    key: CoreKey,
    direction: CipherDirection,
    bit_size: usize,
}

impl RsaCoreEngine {
    pub(crate) fn new(direction: CipherDirection, params: &RsaKey<'_>) -> Result<Self, RsaError> {
        let (key, bit_size) = match params {
            RsaKey::Standard(params) => (
                CoreKey::Standard(StandardKey::new(params)?),
                params.modulus().bits(),
            ),
            RsaKey::PrivateCrt(params) => (
                CoreKey::PrivateCrt(RsaPrivateCrtKey::new_by_half_width(params)?),
                params.modulus().bits(),
            ),
        };
        Ok(Self {
            key,
            direction,
            bit_size,
        })
    }

    pub(crate) fn input_block_size(&self) -> usize {
        match self.direction {
            CipherDirection::Encrypt => self.bit_size.saturating_sub(1) / 8,
            CipherDirection::Decrypt => self.bit_size.div_ceil(8),
        }
    }

    pub(crate) fn output_block_size(&self) -> usize {
        match self.direction {
            CipherDirection::Encrypt => self.bit_size.div_ceil(8),
            CipherDirection::Decrypt => self.bit_size.saturating_sub(1) / 8,
        }
    }

    pub(crate) fn process_block<R: CryptoRng + ?Sized>(
        &self,
        input: &[u8],
        output: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, RsaError> {
        if input.len() > self.bit_size.div_ceil(8) {
            return Err(RsaError::InputTooLarge);
        }

        match &self.key {
            CoreKey::Standard(key) => key.process(input, output, self.direction),
            CoreKey::PrivateCrt(key) => key.process(input, output, self.direction, rng),
        }
    }

    #[cfg(test)]
    pub(crate) fn bucket_bits(&self) -> usize {
        match &self.key {
            CoreKey::Standard(key) => key.bucket_bits(),
            CoreKey::PrivateCrt(key) => key.bucket_bits(),
        }
    }
}

fn bucket(bits: usize) -> Result<usize, RsaError> {
    match bits {
        0..=1024 => Ok(1024),
        1025..=2048 => Ok(2048),
        2049..=3072 => Ok(3072),
        3073..=4096 => Ok(4096),
        _ => Err(RsaError::InvalidModulus),
    }
}

fn fixed<const N: usize>(value: &BigUint, error: RsaError) -> Result<FixedBigUint<N>, RsaError> {
    FixedBigUint::from_be_bytes(&value.to_be_bytes()).map_err(|_| error)
}

fn convert_input<const N: usize>(
    input: &[u8],
    modulus: &FixedBigUint<N>,
) -> Result<FixedBigUint<N>, RsaError> {
    let input = FixedBigUint::from_be_bytes(input).map_err(|_| RsaError::InputTooLarge)?;
    if input <= FixedBigUint::from(1_u8) {
        return Err(RsaError::InputTooSmall);
    }
    if input >= *modulus - FixedBigUint::from(1_u8) {
        return Err(RsaError::InputTooLarge);
    }
    Ok(input)
}

fn convert_output<const N: usize>(
    result: &FixedBigUint<N>,
    output: &mut [u8],
    direction: CipherDirection,
    bit_size: usize,
) -> Result<usize, RsaError> {
    let result_len = result.byte_length_unsigned();
    let output_len = match direction {
        CipherDirection::Encrypt => bit_size.div_ceil(8),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_non_aligned_modulus_uses_the_next_bucket() {
        let modulus = (BigUint::from(1_u8) << 1233) + BigUint::from(159_u8);
        let exponent = BigUint::from(3_u8);
        let params = RsaKeyParameters::new(false, &modulus, &exponent).unwrap();
        let core = RsaCoreEngine::new(CipherDirection::Encrypt, &params.into()).unwrap();

        assert_eq!(core.bit_size, 1234);
        assert_eq!(core.bucket_bits(), 2048);
        let mut output = [0_u8; 155];
        let length = match &core.key {
            CoreKey::Standard(key) => key
                .process(&[2], &mut output, CipherDirection::Encrypt)
                .unwrap(),
            CoreKey::PrivateCrt(_) => unreachable!(),
        };
        assert_eq!(length, 155);
        assert!(output[..154].iter().all(|byte| *byte == 0));
        assert_eq!(output[154], 8);
    }
}
