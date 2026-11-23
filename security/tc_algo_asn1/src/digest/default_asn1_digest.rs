use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_digest::TryDigest;

use crate::AlgoAsn1Error;
use crate::digest::Asn1Digest;

pub(crate) struct DefaultAsn1Digest {
    algorithm: AlgorithmIdentifier,
    inner: Box<dyn tc_algo::digest::Digest>,
}

impl DefaultAsn1Digest {
    pub(crate) fn new(
        algorithm: AlgorithmIdentifier,
        inner: Box<dyn tc_algo::digest::Digest>,
    ) -> Self {
        Self { algorithm, inner }
    }
}

impl TryDigest for DefaultAsn1Digest {
    type Error = AlgoAsn1Error;

    fn digest_size(&self) -> usize {
        self.inner.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.inner.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), AlgoAsn1Error> {
        Ok(self.inner.try_update(input)?)
    }

    fn try_update_byte(&mut self, input: u8) -> Result<(), AlgoAsn1Error> {
        Ok(self.inner.try_update_byte(input)?)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoAsn1Error> {
        Ok(self.inner.try_do_final(output)?)
    }

    fn try_reset(&mut self) -> Result<(), AlgoAsn1Error> {
        Ok(self.inner.try_reset()?)
    }
}

impl Asn1Digest for DefaultAsn1Digest {
    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }
}
