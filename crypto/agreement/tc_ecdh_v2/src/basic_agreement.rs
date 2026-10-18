use tc_ec_core_v2::Curve;

pub struct EcdhBasicAgreement<C: Curve> {
    curve: C,
    d: C::Scalar,
}
