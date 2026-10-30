use std::io::{self, Write};

use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::VerifierCalculator;

pub trait VerifierFactory {
    type Calculator: VerifierCalculator;
    type Error: core::error::Error
        + From<io::Error>
        + From<<Self::Calculator as VerifierCalculator>::Error>
        + Send
        + Sync
        + 'static;

    fn algorithm(&self) -> &AlgorithmIdentifier;

    fn create_calculator(&self) -> Result<Self::Calculator, Self::Error>;

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let mut calculator = self.create_calculator()?;
        calculator.write_all(data)?;
        Ok(calculator.verify(signature)?)
    }
}
