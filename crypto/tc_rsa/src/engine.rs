use tc_bigint::BigInteger;
use tc_cipher::CipherDirection;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaError {
    InvalidModulus,
    InvalidExponent,
    InvalidPrivateExponent,
    InvalidP,
    InvalidQ,
    InvalidDp,
    InvalidDq,
    InvalidQInv,
    EvenModulus,
    EvenPublicExponent,
    InputTooSmall,
    InputTooLarge,
    OutputTooShort,
    FaultyDecryptionOrSigning,
}

impl core::fmt::Display for RsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidModulus => "not a valid RSA modulus",
            Self::InvalidExponent => "not a valid RSA exponent",
            Self::InvalidPrivateExponent => "not a valid RSA private exponent",
            Self::InvalidP => "not a valid RSA P value",
            Self::InvalidQ => "not a valid RSA Q value",
            Self::InvalidDp => "not a valid RSA DP value",
            Self::InvalidDq => "not a valid RSA DQ value",
            Self::InvalidQInv => "not a valid RSA inverse Q value",
            Self::EvenModulus => "RSA modulus is even",
            Self::EvenPublicExponent => "RSA public exponent is even",
            Self::InputTooSmall => "input too small for RSA cipher",
            Self::InputTooLarge => "input too large for RSA cipher",
            Self::OutputTooShort => "output buffer too short for RSA cipher",
            Self::FaultyDecryptionOrSigning => "RSA engine faulty decryption/signing detected",
        })
    }
}

impl core::error::Error for RsaError {}

#[derive(Clone, Copy)]
pub struct RsaPublicParams<'a> {
    modulus: &'a BigInteger,
    exponent: &'a BigInteger,
}

impl<'a> RsaPublicParams<'a> {
    pub fn new(modulus: &'a BigInteger, exponent: &'a BigInteger) -> Result<Self, RsaError> {
        if modulus.sign() <= 0 {
            return Err(RsaError::InvalidModulus);
        }
        if exponent.sign() <= 0 {
            return Err(RsaError::InvalidExponent);
        }
        if !exponent.test_bit(0) {
            return Err(RsaError::EvenPublicExponent);
        }
        if !modulus.test_bit(0) {
            return Err(RsaError::EvenModulus);
        }

        Ok(Self { modulus, exponent })
    }
}

#[derive(Clone, Copy)]
pub struct RsaPrivateParams<'a> {
    modulus: &'a BigInteger,
    private_exponent: &'a BigInteger,
    public_exponent: &'a BigInteger,
    p: &'a BigInteger,
    q: &'a BigInteger,
    dp: &'a BigInteger,
    dq: &'a BigInteger,
    q_inv: &'a BigInteger,
}

impl<'a> RsaPrivateParams<'a> {
    pub fn new(
        modulus: &'a BigInteger,
        private_exponent: &'a BigInteger,
        public_exponent: &'a BigInteger,
        p: &'a BigInteger,
        q: &'a BigInteger,
        dp: &'a BigInteger,
        dq: &'a BigInteger,
        q_inv: &'a BigInteger,
    ) -> Result<Self, RsaError> {
        if modulus.sign() <= 0 {
            return Err(RsaError::InvalidModulus);
        }
        if private_exponent.sign() <= 0 {
            return Err(RsaError::InvalidPrivateExponent);
        }
        if !modulus.test_bit(0) {
            return Err(RsaError::EvenModulus);
        }
        if public_exponent.sign() <= 0 {
            return Err(RsaError::InvalidExponent);
        }
        if p.sign() <= 0 {
            return Err(RsaError::InvalidP);
        }
        if q.sign() <= 0 {
            return Err(RsaError::InvalidQ);
        }
        if dp.sign() <= 0 {
            return Err(RsaError::InvalidDp);
        }
        if dq.sign() <= 0 {
            return Err(RsaError::InvalidDq);
        }
        if q_inv.sign() <= 0 {
            return Err(RsaError::InvalidQInv);
        }

        Ok(Self {
            modulus,
            private_exponent,
            public_exponent,
            p,
            q,
            dp,
            dq,
            q_inv,
        })
    }
}

#[derive(Clone, Copy)]
pub enum RsaKey<'a> {
    Standard(RsaPublicParams<'a>),
    PrivateCrt(RsaPrivateParams<'a>),
}

struct RsaCoreEngine<'a> {
    params: RsaKey<'a>,
    direction: CipherDirection,
    bit_size: u32,
}

impl<'a> RsaCoreEngine<'a> {
    pub fn init(direction: CipherDirection, params: RsaKey<'a>) -> Self {
        let modulus = match params {
            RsaKey::Standard(params) => params.modulus,
            RsaKey::PrivateCrt(params) => params.modulus,
        };

        Self {
            bit_size: modulus.bit_length(),
            direction,
            params,
        }
    }

    pub fn input_block_size(&self) -> usize {
        match self.direction {
            CipherDirection::Encrypt => (self.bit_size.saturating_sub(1) / 8) as usize,
            CipherDirection::Decrypt => ((self.bit_size + 7) / 8) as usize,
        }
    }

    pub fn output_block_size(&self) -> usize {
        match self.direction {
            CipherDirection::Encrypt => ((self.bit_size + 7) / 8) as usize,
            CipherDirection::Decrypt => (self.bit_size.saturating_sub(1) / 8) as usize,
        }
    }

    pub fn convert_input(&self, input: &[u8]) -> Result<BigInteger, RsaError> {
        let max_input_len = ((self.bit_size + 7) / 8) as usize;
        if input.len() > max_input_len {
            return Err(RsaError::InputTooLarge);
        }

        let input = BigInteger::from_bytes_be_unsigned(input);
        if input <= 1 {
            return Err(RsaError::InputTooSmall);
        }

        let modulus = match self.params {
            RsaKey::Standard(params) => params.modulus,
            RsaKey::PrivateCrt(params) => params.modulus,
        };
        if input >= modulus - &BigInteger::from_u32(1) {
            return Err(RsaError::InputTooLarge);
        }

        Ok(input)
    }

    pub fn process_block(&self, input: &BigInteger) -> Result<BigInteger, RsaError> {
        match self.params {
            RsaKey::Standard(params) => Ok(input.mod_pow(params.exponent, params.modulus)),
            RsaKey::PrivateCrt(params) => {
                let m_p = (input % params.p).mod_pow(params.dp, params.p);
                let m_q = (input % params.q).mod_pow(params.dq, params.q);
                let difference = &m_p - &m_q;
                let h = (&difference * params.q_inv).rem_euclid(params.p);
                let result = &(&h * params.q) + &m_q;

                if result.mod_pow(params.public_exponent, params.modulus) != *input {
                    return Err(RsaError::FaultyDecryptionOrSigning);
                }

                Ok(result)
            }
        }
    }

    pub fn convert_output(
        &self,
        result: &BigInteger,
        output: &mut [u8],
    ) -> Result<usize, RsaError> {
        let result_len = result.byte_length_unsigned();
        let output_len = match self.direction {
            CipherDirection::Encrypt => ((self.bit_size + 7) / 8) as usize,
            CipherDirection::Decrypt => result_len,
        };

        if output.len() < output_len || result_len > output_len {
            return Err(RsaError::OutputTooShort);
        }

        output[..output_len].fill(0);
        result
            .try_to_bytes_be_unsigned_into(&mut output[output_len - result_len..output_len])
            .map_err(|_| RsaError::OutputTooShort)?;

        Ok(output_len)
    }
}
