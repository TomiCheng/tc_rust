use rand_core::CryptoRng;
use tc_ec_core::Curve;

/// BC's `ECKeyGenerationParameters`: the generator G, which carries its curve and so the
/// whole domain, and the random source.
pub struct EcKeyGenerationParams<'a, C: Curve> {
    pub(crate) g: C::Point,
    pub(crate) rng: &'a mut dyn CryptoRng,
}

impl<'a, C: Curve> EcKeyGenerationParams<'a, C> {
    /// G is checked when a generator is initialized with these.
    pub fn new(g: C::Point, rng: &'a mut dyn CryptoRng) -> Self {
        Self { g, rng }
    }
}
