use tc_algo::Params;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_signer::SignerInit;

use crate::AlgoAsn1Error;

// A Signer of tc_signer with the AlgorithmIdentifier it goes by, so that it goes wherever a tc_signer
// Signer does. The key tells the direction, as in tc_algo: a private key signs and a public key
// verifies
pub trait Asn1Signer:
    tc_signer::Signer<Error = AlgoAsn1Error> + SignerInit<dyn Params, Error = AlgoAsn1Error>
{
    // What a certificate, a CRL or a SignerInfo records for this signature; a TBS takes it before
    // it is signed
    fn algorithm(&self) -> &AlgorithmIdentifier;

    // generate_signature with an output of its own, the value to go into a BIT STRING or an OCTET
    // STRING as the structure has it
    fn sign(&mut self) -> Result<Vec<u8>, AlgoAsn1Error> {
        let mut output = vec![0; self.max_signature_size()];
        let written = self.generate_signature(&mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
