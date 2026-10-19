use crate::DsaKCalculator;
use rand_core::CryptoRng;
use tc_bigint::{PaddedBigUint, RandomBits};
use tc_zeroize::Zeroize;

/// BC's `RandomDsaKCalculator`: k drawn from the random source `R` it holds. `R` can be a
/// `&mut` borrow, so the caller keeps the source.
pub struct RandomDsaKCalculator<R> {
    rng: R,
    n: Option<PaddedBigUint>,
}

impl<R> RandomDsaKCalculator<R> {
    /// A calculator drawing from `rng`, to be initialized. Constant time.
    pub const fn new(rng: R) -> Self {
        Self { rng, n: None }
    }
}

impl<R: CryptoRng> DsaKCalculator<PaddedBigUint> for RandomDsaKCalculator<R> {
    /// Keeps n; d and the message are not read. Variable time: only for public values, as
    /// n is.
    fn init(&mut self, n: &PaddedBigUint, _d: &PaddedBigUint, _message: &[u8]) {
        self.n = Some(n.clone());
    }

    /// As BC does, n's bit length of random bits, drawn again until they fall in [1, n − 1].
    /// Constant time in k, apart from how many are drawn, as in all drawing by rejection.
    fn next_k(&mut self) -> PaddedBigUint {
        let n = self.n.as_ref().expect("the calculator is initialized");
        let one = PaddedBigUint::from(1u8);
        loop {
            let mut k = PaddedBigUint::random_bits(&mut self.rng, n.bits());
            if k >= one && k < *n {
                return k;
            }
            k.zeroize();
        }
    }
}
