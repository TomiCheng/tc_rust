use std::sync::Arc;

use tc_algo::Algo;
use tc_asn1::{Encode, EncodingOptions};
use tc_asn1_pkcs::{Pkcs1Algorithm, RsassaPssParams};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoAsn1Error;
use crate::der::decode_all;
use crate::digest::{Asn1Digest, DefaultAsn1Digest, DigestEntry, DigestProvider};

// The rows in the order they are tried, the last registered first, and the algorithms the digests
// come from
pub(crate) struct DefaultDigestProvider {
    algo: Arc<dyn Algo>,
    rows: Vec<Box<dyn DigestEntry>>,
}

impl DefaultDigestProvider {
    pub(crate) fn new(algo: Arc<dyn Algo>, rows: Vec<Box<dyn DigestEntry>>) -> Self {
        Self { algo, rows }
    }

    fn digest(
        &self,
        row: &dyn DigestEntry,
        algorithm: AlgorithmIdentifier,
    ) -> Result<Box<dyn Asn1Digest>, AlgoAsn1Error> {
        let inner = self.algo.digest().get_by_name(row.name())?;
        Ok(Box::new(DefaultAsn1Digest::new(algorithm, inner)))
    }
}

impl DigestProvider for DefaultDigestProvider {
    fn get_by_name(&self, name: &str) -> Result<Box<dyn Asn1Digest>, AlgoAsn1Error> {
        let row = self
            .rows
            .iter()
            .find(|row| {
                row.name().eq_ignore_ascii_case(name)
                    || row
                        .aliases()
                        .iter()
                        .any(|alias| alias.eq_ignore_ascii_case(name))
            })
            .ok_or(AlgoAsn1Error::UnknownDigest)?;
        self.digest(row.as_ref(), row.algorithm().clone())
    }

    fn get_by_id(
        &self,
        algorithm: &AlgorithmIdentifier,
    ) -> Result<Box<dyn Asn1Digest>, AlgoAsn1Error> {
        let row = self
            .rows
            .iter()
            .find(|row| row.matches(algorithm))
            .ok_or(AlgoAsn1Error::UnknownDigest)?;
        self.digest(row.as_ref(), algorithm.clone())
    }

    fn get_by_signer(
        &self,
        signature: &AlgorithmIdentifier,
    ) -> Result<Box<dyn Asn1Digest>, AlgoAsn1Error> {
        let row = if *signature.algorithm() == Pkcs1Algorithm::RSASSA_PSS {
            // Absent parameters are those of RFC 4055, with SHA-1
            let params = match signature.parameters() {
                Some(parameters) => decode_all::<RsassaPssParams>(
                    &parameters.encode_to_vec(&EncodingOptions::DER)?,
                )?,
                None => RsassaPssParams::default(),
            };
            self.rows
                .iter()
                .find(|row| row.matches(params.hash_algorithm()))
        } else {
            self.rows
                .iter()
                .find(|row| row.signers().contains(signature.algorithm()))
        }
        .ok_or(AlgoAsn1Error::UnknownDigest)?;
        self.digest(row.as_ref(), row.algorithm().clone())
    }
}
