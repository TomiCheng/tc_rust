//! Cofactor ECDH agreement。

use alloc::sync::Arc;

use tc_ec_core::{Point, SecretCurve, SecretField, clean_point};

use crate::basic::{agreement_x, validate_private_key};
use crate::{EcdhError, EcdhScalar};

/// P1363 ECSVDP-DHC cofactor agreement。
pub struct EcdhcBasicAgreement<C: SecretCurve>
where
    C::Field: SecretField,
    C::Scalar: EcdhScalar,
{
    curve: Arc<C>,
    d: C::Scalar,
}

impl<C: SecretCurve> EcdhcBasicAgreement<C>
where
    C::Field: SecretField,
    C::Scalar: EcdhScalar,
{
    /// 驗證域參數與 `d in [1, n - 1]` 後建立 agreement。
    pub fn new(curve: Arc<C>, d: C::Scalar) -> Result<Self, EcdhError> {
        validate_private_key(curve.as_ref(), &d)?;
        Ok(Self { curve, d })
    }

    /// 曲線域參數。
    pub fn curve(&self) -> &Arc<C> {
        &self.curve
    }

    /// 計算 cofactor ECDH 結果的 affine X 座標整數。
    pub fn calculate_agreement(&self, peer: &C::Point) -> Result<C::Scalar, EcdhError> {
        let n = self.curve.order().ok_or(EcdhError::MissingCurveOrder)?;
        let h = self.curve.cofactor().ok_or(EcdhError::MissingCofactor)?;
        let hd = self
            .d
            .mul_mod_ct(h, n)
            .ok_or(EcdhError::InvalidCurveOrder)?;
        let point = clean_point(&self.curve, peer).map_err(|_| EcdhError::InvalidPublicKey)?;
        if point.is_identity() {
            return Err(EcdhError::InvalidPublicKey);
        }

        agreement_x::<C>(&point, &hd)
    }
}
