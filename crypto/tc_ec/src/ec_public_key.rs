use crate::EcDomain;
use tc_ec_core_v2::Curve;

pub struct EcPublicKey<C: Curve> {
    domain: EcDomain<C>,
    q: C::Point,
}
