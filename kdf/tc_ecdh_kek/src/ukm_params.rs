use alloc::vec::Vec;

/// Bouncy Castle's `ParametersWithUkm`: the private-key parameters of the
/// agreement underneath, and the sender's UKM (user keying material), which
/// goes into the KDF's `entityUInfo`. It is a container alone; `init` reads
/// it.
#[derive(Clone)]
pub struct UkmParams<P> {
    params: P,
    ukm: Vec<u8>,
}

impl<P> UkmParams<P> {
    /// Parameters without a UKM, as Bouncy Castle without `ParametersWithUkm`.
    /// Constant time.
    pub fn new(params: P) -> Self {
        Self {
            params,
            ukm: Vec::new(),
        }
    }

    /// Sets the UKM; an empty one means none. Constant time.
    pub fn with_ukm(mut self, ukm: Vec<u8>) -> Self {
        self.ukm = ukm;
        self
    }

    /// The private-key parameters of the agreement underneath. Constant time.
    pub fn params(&self) -> &P {
        &self.params
    }

    /// The UKM. Constant time.
    pub fn ukm(&self) -> &[u8] {
        &self.ukm
    }
}
