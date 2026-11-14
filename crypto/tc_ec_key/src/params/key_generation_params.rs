use tc_ec_core::Curve;

/// BC's `ECKeyGenerationParameters` without its random source, which a generator takes when
/// it is constructed: the generator G, which carries its curve and so the whole domain.
pub struct EcKeyGenerationParams<C: Curve> {
    pub(crate) g: C::Point,
}

impl<C: Curve> EcKeyGenerationParams<C> {
    /// G is checked when a generator is initialized with these.
    pub fn new(g: C::Point) -> Self {
        Self { g }
    }
}

impl<C: Curve> Clone for EcKeyGenerationParams<C> {
    fn clone(&self) -> Self {
        Self { g: self.g.clone() }
    }
}
