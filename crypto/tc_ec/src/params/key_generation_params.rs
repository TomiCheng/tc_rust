use crate::EcDomain;
use rand_core::CryptoRng;
use tc_ec_core_v2::Curve;

/// BC's `ECKeyGenerationParameters`: the domain to generate in and the random source.
pub struct EcKeyGenerationParams<'a, C: Curve> {
    domain: EcDomain<C>,
    rng: &'a mut dyn CryptoRng,
}
