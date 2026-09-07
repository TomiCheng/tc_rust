//! 標準 ECDH agreement。

use alloc::sync::Arc;

use tc_ec_core::{Point, SecretCurve, SecretField, clean_point, multiply_secret, scalar_mul};

use crate::{EcdhError, EcdhScalar};

/// P1363 ECSVDP-DH agreement。
pub struct EcdhBasicAgreement<C: SecretCurve>
where
    C::Field: SecretField,
    C::Scalar: EcdhScalar,
{
    curve: Arc<C>,
    d: C::Scalar,
}

impl<C: SecretCurve> EcdhBasicAgreement<C>
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

    /// 計算對方公鑰的 affine X 座標整數。
    pub fn calculate_agreement(&self, peer: &C::Point) -> Result<C::Scalar, EcdhError> {
        let n = self.curve.order().ok_or(EcdhError::MissingCurveOrder)?;
        let h = self.curve.cofactor().ok_or(EcdhError::MissingCofactor)?;
        let mut d = self.d;
        let mut point = clean_point(&self.curve, peer).map_err(|_| EcdhError::InvalidPublicKey)?;
        if point.is_identity() {
            return Err(EcdhError::InvalidPublicKey);
        }

        if *h != C::Scalar::one() {
            let inverse = h.inverse_vartime(n).ok_or(EcdhError::InvalidCofactor)?;
            d = d
                .mul_mod_ct(&inverse, n)
                .ok_or(EcdhError::InvalidCurveOrder)?;
            point = scalar_mul::<C>(&point, h);
        }

        agreement_x::<C>(&point, &d)
    }
}

pub(crate) fn agreement_x<C: SecretCurve>(
    point: &C::Point,
    scalar: &C::Scalar,
) -> Result<C::Scalar, EcdhError>
where
    C::Field: SecretField,
    C::Scalar: EcdhScalar,
{
    let secret = multiply_secret::<C>(point, &scalar.to_le_bytes_fixed())
        .map_err(|_| EcdhError::CurveOperation)?;
    if secret.is_identity().unwrap_u8() == 1 {
        return Err(EcdhError::InvalidAgreement);
    }
    let point = secret.reveal();
    let x = point.x().ok_or(EcdhError::InvalidAgreement)?;
    C::field_element_to_scalar(&x).ok_or(EcdhError::InvalidAgreement)
}

pub(crate) fn validate_private_key<C: SecretCurve>(
    curve: &C,
    d: &C::Scalar,
) -> Result<(), EcdhError>
where
    C::Scalar: EcdhScalar,
{
    let n = curve.order().ok_or(EcdhError::MissingCurveOrder)?;
    let h = curve.cofactor().ok_or(EcdhError::MissingCofactor)?;
    if *n <= C::Scalar::one() {
        return Err(EcdhError::InvalidCurveOrder);
    }
    if C::scalar_is_zero(h) {
        return Err(EcdhError::InvalidCofactor);
    }
    if C::scalar_is_zero(d) || d >= n {
        return Err(EcdhError::InvalidPrivateKey);
    }
    Ok(())
}
