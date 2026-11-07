use tc_algo_v2::AlgoError;
use tc_algo_v2::digest::Digest;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use super::default_digest_calculator::DefaultDigestCalculator;
use crate::digest::DigestCalculator;

pub trait DigestFactory {
    fn algorithm(&self) -> &AlgorithmIdentifier;

    // The length of the hash, in bytes
    fn digest_size(&self) -> usize;

    fn create(&self) -> Result<Box<dyn Digest>, AlgoError>;

    fn create_calculator(&self) -> Result<Box<dyn DigestCalculator>, AlgoError> {
        Ok(Box::new(DefaultDigestCalculator::new(self.create()?)))
    }

    fn digest(&self, data: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let mut digest = self.create()?;
        digest.update(data);
        Ok(digest.finalize())
    }
}
