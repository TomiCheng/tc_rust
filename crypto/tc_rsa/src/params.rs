//! RSA 金鑰參數。

use tc_bigint::BigUint;

use crate::RsaError;

/// 公開金鑰或非 CRT 私鑰的參數。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsaKeyParameters<'a> {
    is_private: bool,
    modulus: &'a BigUint,
    exponent: &'a BigUint,
}

impl<'a> RsaKeyParameters<'a> {
    /// 建立 RSA 金鑰參數。
    ///
    /// `exponent` 對公開金鑰是 `e`，對私鑰是 `d`。
    pub fn new(
        is_private: bool,
        modulus: &'a BigUint,
        exponent: &'a BigUint,
    ) -> Result<Self, RsaError> {
        validate_modulus(modulus)?;
        if exponent.is_zero() {
            return Err(if is_private {
                RsaError::InvalidPrivateExponent
            } else {
                RsaError::InvalidExponent
            });
        }
        if !exponent.test_bit(0) {
            return Err(if is_private {
                RsaError::InvalidPrivateExponent
            } else {
                RsaError::EvenPublicExponent
            });
        }

        Ok(Self {
            is_private,
            modulus,
            exponent,
        })
    }

    /// 回傳此參數是否包含私密指數。
    pub const fn is_private(&self) -> bool {
        self.is_private
    }

    /// 回傳模數。
    pub const fn modulus(&self) -> &'a BigUint {
        self.modulus
    }

    /// 回傳公開或私密指數。
    pub const fn exponent(&self) -> &'a BigUint {
        self.exponent
    }
}

/// 含中國剩餘定理因子的 RSA 私鑰參數。
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RsaPrivateCrtKeyParameters<'a> {
    modulus: &'a BigUint,
    public_exponent: &'a BigUint,
    private_exponent: &'a BigUint,
    p: &'a BigUint,
    q: &'a BigUint,
    dp: &'a BigUint,
    dq: &'a BigUint,
    q_inv: &'a BigUint,
}

impl<'a> RsaPrivateCrtKeyParameters<'a> {
    /// 建立 CRT 私鑰參數。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        modulus: &'a BigUint,
        public_exponent: &'a BigUint,
        private_exponent: &'a BigUint,
        p: &'a BigUint,
        q: &'a BigUint,
        dp: &'a BigUint,
        dq: &'a BigUint,
        q_inv: &'a BigUint,
    ) -> Result<Self, RsaError> {
        validate_modulus(modulus)?;
        validate_nonzero(public_exponent, RsaError::InvalidExponent)?;
        if !public_exponent.test_bit(0) {
            return Err(RsaError::EvenPublicExponent);
        }
        validate_nonzero(private_exponent, RsaError::InvalidPrivateExponent)?;
        if !private_exponent.test_bit(0) {
            return Err(RsaError::InvalidPrivateExponent);
        }
        validate_odd(p, RsaError::InvalidP)?;
        validate_odd(q, RsaError::InvalidQ)?;
        validate_nonzero(dp, RsaError::InvalidDp)?;
        validate_nonzero(dq, RsaError::InvalidDq)?;
        validate_nonzero(q_inv, RsaError::InvalidQInv)?;

        Ok(Self {
            modulus,
            public_exponent,
            private_exponent,
            p,
            q,
            dp,
            dq,
            q_inv,
        })
    }

    pub const fn modulus(&self) -> &'a BigUint {
        self.modulus
    }

    pub const fn public_exponent(&self) -> &'a BigUint {
        self.public_exponent
    }

    pub const fn private_exponent(&self) -> &'a BigUint {
        self.private_exponent
    }

    pub const fn p(&self) -> &'a BigUint {
        self.p
    }

    pub const fn q(&self) -> &'a BigUint {
        self.q
    }

    pub const fn dp(&self) -> &'a BigUint {
        self.dp
    }

    pub const fn dq(&self) -> &'a BigUint {
        self.dq
    }

    pub const fn q_inv(&self) -> &'a BigUint {
        self.q_inv
    }
}

/// 可交給 RSA 引擎的金鑰種類。
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RsaKey<'a> {
    Standard(RsaKeyParameters<'a>),
    PrivateCrt(RsaPrivateCrtKeyParameters<'a>),
}

impl<'a> From<RsaKeyParameters<'a>> for RsaKey<'a> {
    fn from(value: RsaKeyParameters<'a>) -> Self {
        Self::Standard(value)
    }
}

impl<'a> From<RsaPrivateCrtKeyParameters<'a>> for RsaKey<'a> {
    fn from(value: RsaPrivateCrtKeyParameters<'a>) -> Self {
        Self::PrivateCrt(value)
    }
}

fn validate_modulus(modulus: &BigUint) -> Result<(), RsaError> {
    validate_nonzero(modulus, RsaError::InvalidModulus)?;
    if !modulus.test_bit(0) {
        return Err(RsaError::EvenModulus);
    }
    if modulus.bits() > 4096 {
        return Err(RsaError::InvalidModulus);
    }

    // TODO: 整合 tc_bigint 質數模組後，補上小質因數篩選與模數合成性檢查。
    Ok(())
}

fn validate_nonzero(value: &BigUint, error: RsaError) -> Result<(), RsaError> {
    if value.is_zero() { Err(error) } else { Ok(()) }
}

fn validate_odd(value: &BigUint, error: RsaError) -> Result<(), RsaError> {
    validate_nonzero(value, error)?;
    if value.test_bit(0) {
        Ok(())
    } else {
        Err(error)
    }
}
