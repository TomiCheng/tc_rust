use tc_algo::Params;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit};

use crate::AlgoAsn1Error;

// A BufferedCipher of tc_buffered_cipher with the AlgorithmIdentifier it goes by, so that it goes
// wherever a BufferedCipher does. init takes the key alone; the parameters, such as the IV, come
// with the AlgorithmIdentifier
pub trait Asn1Cipher:
    BufferedCipher<Error = AlgoAsn1Error> + BufferedCipherInit<dyn Params, Error = AlgoAsn1Error>
{
    // What an EnvelopedData records for the message. A cipher by name draws fresh parameters for
    // each message it encrypts, so it is read after init
    fn algorithm(&self) -> &AlgorithmIdentifier;

    // process_bytes with an output of its own
    fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoAsn1Error> {
        let mut output = vec![0; self.update_output_len(input.len())?];
        let written = self.process_bytes(input, &mut output)?;
        output.truncate(written);
        Ok(output)
    }

    // do_final with an output of its own
    fn finalize(&mut self) -> Result<Vec<u8>, AlgoAsn1Error> {
        let mut output = vec![0; self.output_len(0)?];
        let written = self.do_final(&mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
