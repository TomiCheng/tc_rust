use rand_core::CryptoRng;

use crate::{AlgoError, Params};

// A random source in its own right, so next_u64 and fill_bytes are those of CryptoRng and it can be
// given wherever one is wanted. It is seeded when it is created, so it works without init. It
// reseeds by itself when it must, as Bouncy Castle's SP800SecureRandom does, since CryptoRng cannot
// report an error
pub trait Drbg: CryptoRng {
    // Seeds it again with what the params give, such as a nonce or a personalization string
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError>;

    // Draws new entropy from the random source of DefaultAlgoBuilder, mixed with the input
    fn reseed(&mut self, additional_input: &[u8]) -> Result<(), AlgoError>;
}
