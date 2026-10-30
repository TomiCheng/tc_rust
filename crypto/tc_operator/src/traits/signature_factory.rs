use std::io::{self, Write};

use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::SignatureCalculator;

pub trait SignatureFactory {
    type Calculator: SignatureCalculator;
    type Error: core::error::Error
        + From<io::Error>
        + From<<Self::Calculator as SignatureCalculator>::Error>
        + Send
        + Sync
        + 'static;

    fn algorithm(&self) -> &AlgorithmIdentifier;

    fn create_calculator(&self) -> Result<Self::Calculator, Self::Error>;

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut calculator = self.create_calculator()?;
        calculator.write_all(data)?;
        Ok(calculator.finish()?)
    }
}
