use alloc::sync::Arc;

use tc_ec_core::{Point, SecretCurve, SecretField, clean_point, multiply_secret};

use crate::{EcdsaError, EcdsaScalar};

/// ECDSA 簽章金鑰。
pub struct SigningKey<C: SecretCurve>
where
    C::Field: SecretField,
    C::Scalar: EcdsaScalar,
{
    curve: Arc<C>,
    generator: C::Point,
    d: C::Scalar,
}

impl<C: SecretCurve> SigningKey<C>
where
    C::Field: SecretField,
    C::Scalar: EcdsaScalar,
{
    /// 驗證域參數與 `d in [1, n - 1]` 後建立簽章金鑰。
    pub fn new(curve: Arc<C>, generator: C::Point, d: C::Scalar) -> Result<Self, EcdsaError> {
        validate_order(curve.as_ref())?;
        let n = curve.order().expect("前一步已驗證曲線階");
        if d.is_zero() || d >= *n {
            return Err(EcdsaError::InvalidPrivateKey);
        }
        let generator =
            clean_point(&curve, &generator).map_err(|_| EcdsaError::InvalidGenerator)?;
        if generator.is_identity() {
            return Err(EcdsaError::InvalidGenerator);
        }
        Ok(Self {
            curve,
            generator,
            d,
        })
    }

    /// 曲線域參數。
    pub fn curve(&self) -> &Arc<C> {
        &self.curve
    }

    /// 標準基點。
    pub fn generator(&self) -> &C::Point {
        &self.generator
    }

    /// 私密純量。
    pub fn private_scalar(&self) -> &C::Scalar {
        &self.d
    }

    /// 以固定排程計算 `Q = dG` 並建立對應的驗證金鑰。
    pub fn verifying_key(&self) -> Result<VerifyingKey<C>, EcdsaError> {
        let q = multiply_secret::<C>(&self.generator, &self.d.to_le_bytes_fixed())
            .map_err(|_| EcdsaError::CurveOperation)?
            .reveal();
        VerifyingKey::new(self.curve.clone(), self.generator.clone(), q)
    }
}

/// ECDSA 驗證金鑰。
pub struct VerifyingKey<C: SecretCurve>
where
    C::Field: SecretField,
    C::Scalar: EcdsaScalar,
{
    curve: Arc<C>,
    generator: C::Point,
    q: C::Point,
}

impl<C: SecretCurve> VerifyingKey<C>
where
    C::Field: SecretField,
    C::Scalar: EcdsaScalar,
{
    /// 驗證域參數、基點與非無窮遠公開點後建立驗證金鑰。
    pub fn new(curve: Arc<C>, generator: C::Point, q: C::Point) -> Result<Self, EcdsaError> {
        validate_order(curve.as_ref())?;
        let generator =
            clean_point(&curve, &generator).map_err(|_| EcdsaError::InvalidGenerator)?;
        if generator.is_identity() {
            return Err(EcdsaError::InvalidGenerator);
        }
        let q = clean_point(&curve, &q).map_err(|_| EcdsaError::InvalidPublicKey)?;
        if q.is_identity() {
            return Err(EcdsaError::InvalidPublicKey);
        }
        Ok(Self {
            curve,
            generator,
            q,
        })
    }

    /// 曲線域參數。
    pub fn curve(&self) -> &Arc<C> {
        &self.curve
    }

    /// 標準基點。
    pub fn generator(&self) -> &C::Point {
        &self.generator
    }

    /// 公開點 `Q`。
    pub fn public_point(&self) -> &C::Point {
        &self.q
    }
}

fn validate_order<C: SecretCurve>(curve: &C) -> Result<(), EcdsaError>
where
    C::Scalar: EcdsaScalar,
{
    let n = curve.order().ok_or(EcdsaError::MissingCurveOrder)?;
    if *n <= C::Scalar::one() || !n.is_odd() {
        return Err(EcdsaError::InvalidCurveOrder);
    }
    Ok(())
}
