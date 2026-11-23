use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_digest::TryDigest;

use crate::AlgoAsn1Error;

// A TryDigest of tc_digest with the AlgorithmIdentifier it goes by, so that it goes wherever a
// TryDigest does
pub trait Asn1Digest: TryDigest<Error = AlgoAsn1Error> {
    // What a SignerInfo, a CertID or a MessageImprint records for this digest
    fn algorithm(&self) -> &AlgorithmIdentifier;

    // try_do_final with an output of its own, then the next message
    fn finalize(&mut self) -> Result<Vec<u8>, AlgoAsn1Error> {
        let mut output = vec![0; self.digest_size()];
        let written = self.try_do_final(&mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
