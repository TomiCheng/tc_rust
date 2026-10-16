use tc_ec_core_v2::Curve;

pub struct EcDomain<C: Curve> {
    curve: C,
    g: C::Point,
}
