use tc_algo::Params;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_macs::MacInit;

use crate::AlgoAsn1Error;
use crate::mac::Asn1Mac;

pub(crate) struct DefaultAsn1Mac {
    algorithm: AlgorithmIdentifier,
    inner: Box<dyn tc_algo::mac::Mac>,
}

impl DefaultAsn1Mac {
    pub(crate) fn new(algorithm: AlgorithmIdentifier, inner: Box<dyn tc_algo::mac::Mac>) -> Self {
        Self { algorithm, inner }
    }
}

impl tc_macs::Mac for DefaultAsn1Mac {
    type Error = AlgoAsn1Error;

    fn mac_size(&self) -> usize {
        self.inner.mac_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoAsn1Error> {
        Ok(self.inner.update(input)?)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoAsn1Error> {
        Ok(self.inner.do_final(output)?)
    }

    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl MacInit<dyn Params> for DefaultAsn1Mac {
    type Error = AlgoAsn1Error;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoAsn1Error> {
        Ok(self.inner.init(params)?)
    }
}

impl Asn1Mac for DefaultAsn1Mac {
    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }
}
