use crate::EcError;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;
use tc_ec_core::{Curve, Point};
use tc_zeroize::Zeroize;

/// BC's `ECPrivateKeyParameters`: the scalar d, with the generator G standing for the
/// domain, since a point carries its curve and the curve its order and cofactor. d is
/// wiped when the key is dropped.
#[derive(Clone)]
pub struct EcPrivateKey<C: Curve<Scalar = PaddedBigUint>> {
    g: C::Point,
    d: PaddedBigUint,
}

impl<C: Curve<Scalar = PaddedBigUint>> EcPrivateKey<C> {
    /// BC's `ValidatePrivateScalar`: d must lie in `[1, n - 1]`. Constant time in d; only
    /// whether it does is revealed.
    pub fn new(g: C::Point, d: PaddedBigUint) -> Result<Self, EcError> {
        let curve = g.curve();
        let n = curve.order().ok_or(EcError::MissingOrder)?;
        if d < PaddedBigUint::from(1u8) || d >= *n {
            return Err(EcError::InvalidPrivateScalar);
        }
        Ok(Self { g, d })
    }

    pub fn g(&self) -> &C::Point {
        &self.g
    }

    pub fn d(&self) -> &PaddedBigUint {
        &self.d
    }
}

/// BC's `IsPrivate`: always. Constant time.
impl<C: Curve<Scalar = PaddedBigUint>> AsymmetricKeyParams for EcPrivateKey<C> {
    fn is_private_key(&self) -> bool {
        true
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Drop for EcPrivateKey<C> {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}
