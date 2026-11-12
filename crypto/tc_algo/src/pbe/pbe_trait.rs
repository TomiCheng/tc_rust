use crate::{AlgoError, Params};

// Bouncy Castle's PbeUtilities: a password, a salt and an iteration count give the params of a
// cipher or MAC. It does no encryption of its own: the params go to the row named by target. That
// stands in for CreateEngine, which returns an object that may be either
pub trait Pbe {
    // The row in algo.cipher() or algo.mac() that the params are for
    fn target(&self) -> &str;

    // The same password, salt and count give the same params, IV included, so use a new salt for
    // each message
    fn generate_params(
        &self,
        password: &str,
        salt: &[u8],
        iterations: usize,
    ) -> Result<Box<dyn Params>, AlgoError>;
}
