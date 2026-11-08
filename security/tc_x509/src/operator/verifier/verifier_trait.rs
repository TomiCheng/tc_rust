use crate::X509Error;

// BC's IVerifier: what a verifier calculator gives once the signed data is written into it. A wrong
// signature is Ok(false), not an error, so look at the answer. It takes &mut self, as the signer
// under it changes when it verifies
pub trait Verifier {
    fn is_verified(&mut self, signature: &[u8]) -> Result<bool, X509Error>;
}
