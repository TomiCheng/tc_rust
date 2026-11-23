use tc_algo::Params;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_constant_time::fixed_time_eq;
use tc_macs::MacInit;

use crate::AlgoAsn1Error;

// A Mac of tc_macs with the AlgorithmIdentifier it goes by, so that it goes wherever a tc_macs Mac
// does
pub trait Asn1Mac:
    tc_macs::Mac<Error = AlgoAsn1Error> + MacInit<dyn Params, Error = AlgoAsn1Error>
{
    // What an AuthenticatedData records for this MAC
    fn algorithm(&self) -> &AlgorithmIdentifier;

    // do_final with an output of its own
    fn finalize(&mut self) -> Result<Vec<u8>, AlgoAsn1Error> {
        let mut output = vec![0; self.mac_size()];
        let written = self.do_final(&mut output)?;
        output.truncate(written);
        Ok(output)
    }

    // Whether `tag` is the message's tag, compared in constant time, since comparing with `==` stops
    // at the first difference and tells an attacker how much of a forged tag is right
    fn verify(&mut self, tag: &[u8]) -> Result<bool, AlgoAsn1Error> {
        Ok(fixed_time_eq(&self.finalize()?, tag))
    }
}
