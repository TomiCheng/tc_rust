use crate::{AlgoError, Params};

// Bouncy Castle's KemUtilities, whose IKemEncapsulator and IKemDecapsulator are one trait here: the
// secret comes from the algorithm, and only the encapsulation goes to the other side
pub trait Kem {
    // Takes the other side's public key, and gives the encapsulation to send and the secret to keep,
    // the caller's to wipe
    fn encapsulate(&self, public_key: &dyn Params) -> Result<(Vec<u8>, Vec<u8>), AlgoError>;

    // Takes this side's private key and the encapsulation received, and gives the same secret
    fn decapsulate(
        &self,
        private_key: &dyn Params,
        encapsulation: &[u8],
    ) -> Result<Vec<u8>, AlgoError>;
}
