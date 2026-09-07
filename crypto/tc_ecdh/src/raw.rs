//! ECDH 的定長 shared-secret 編碼。

use alloc::{sync::Arc, vec::Vec};

use tc_ec_core::{SecretCurve, SecretField};

use crate::{EcdhBasicAgreement, EcdhError, EcdhScalar, EcdhcBasicAgreement};

/// 回傳標準 ECDH 定長 X 座標的 agreement。
pub struct EcdhRawAgreement<C: SecretCurve>
where
    C::Field: SecretField,
    C::Scalar: EcdhScalar,
{
    inner: EcdhBasicAgreement<C>,
}

impl<C: SecretCurve> EcdhRawAgreement<C>
where
    C::Field: SecretField,
    C::Scalar: EcdhScalar,
{
    /// 建立標準 ECDH raw agreement。
    pub fn new(curve: Arc<C>, d: C::Scalar) -> Result<Self, EcdhError> {
        Ok(Self {
            inner: EcdhBasicAgreement::new(curve, d)?,
        })
    }

    /// Shared secret 的定長 byte 數。
    #[must_use]
    pub fn agreement_size(&self) -> usize {
        self.inner.curve().field_size().div_ceil(8)
    }

    /// 計算定長 big-endian affine X 座標。
    pub fn calculate_agreement(&self, peer: &C::Point) -> Result<Vec<u8>, EcdhError> {
        Ok(self
            .inner
            .calculate_agreement(peer)?
            .to_be_bytes_padded(self.agreement_size()))
    }
}

/// 回傳 cofactor ECDH 定長 X 座標的 agreement。
pub struct EcdhcRawAgreement<C: SecretCurve>
where
    C::Field: SecretField,
    C::Scalar: EcdhScalar,
{
    inner: EcdhcBasicAgreement<C>,
}

impl<C: SecretCurve> EcdhcRawAgreement<C>
where
    C::Field: SecretField,
    C::Scalar: EcdhScalar,
{
    /// 建立 cofactor ECDH raw agreement。
    pub fn new(curve: Arc<C>, d: C::Scalar) -> Result<Self, EcdhError> {
        Ok(Self {
            inner: EcdhcBasicAgreement::new(curve, d)?,
        })
    }

    /// Shared secret 的定長 byte 數。
    #[must_use]
    pub fn agreement_size(&self) -> usize {
        self.inner.curve().field_size().div_ceil(8)
    }

    /// 計算定長 big-endian affine X 座標。
    pub fn calculate_agreement(&self, peer: &C::Point) -> Result<Vec<u8>, EcdhError> {
        Ok(self
            .inner
            .calculate_agreement(peer)?
            .to_be_bytes_padded(self.agreement_size()))
    }
}
