use crate::EcDomain;
use tc_ec_core_v2::Curve;

pub struct EcPrivateKey<C: Curve> {
    domain: EcDomain<C>,
    d: C::Scalar,
}
