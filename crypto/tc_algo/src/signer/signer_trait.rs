use tc_signer::SignerInit;

use crate::{AlgoError, Params};

// A Signer of tc_signer, with AlgoError for its errors and an init taking any params, so that every
// row fits behind Box<dyn Signer> and still goes wherever a tc_signer Signer does. The key tells the
// direction: a private key signs, and a public key verifies
pub trait Signer:
    tc_signer::Signer<Error = AlgoError> + SignerInit<dyn Params, Error = AlgoError>
{
    // generate_signature with an output of its own
    fn sign(&mut self) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.max_signature_size()];
        let written = self.generate_signature(&mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
