use tc_algo::digest::DigestProvider;
use tc_asn1::{Asn1Integer, Asn1Object, Encode, EncodingOptions};
use tc_asn1_cmp::{CertStatus, CmpCertificate, PkiStatusInfo};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_constant_time::fixed_time_eq;

use crate::CmpError;

#[derive(Clone, Copy, Debug)]
pub struct CertificateStatus<'a> {
    status: &'a CertStatus,
}

impl<'a> From<&'a CertStatus> for CertificateStatus<'a> {
    fn from(status: &'a CertStatus) -> Self {
        Self { status }
    }
}

impl CertificateStatus<'_> {
    pub fn cert_req_id(&self) -> &Asn1Integer {
        self.status.cert_req_id()
    }

    pub fn status_info(&self) -> Option<&PkiStatusInfo> {
        self.status.status_info()
    }

    pub fn hash_algorithm(&self) -> Option<&AlgorithmIdentifier> {
        self.status.hash_alg()
    }

    pub fn to_asn1(&self) -> &CertStatus {
        self.status
    }

    /// When hashAlg is absent, the caller supplies the digest implied by the certificate signature.
    pub fn is_verified(
        &self,
        certificate: &CmpCertificate,
        digests: &dyn DigestProvider,
        implicit_digest: Option<&AlgorithmIdentifier>,
    ) -> Result<bool, CmpError> {
        let algorithm = self
            .hash_algorithm()
            .or(implicit_digest)
            .ok_or(CmpError::Invalid("missing certConf digest algorithm"))?;
        let expected = certificate_hash(certificate, algorithm, digests)?;
        Ok(fixed_time_eq(&expected, self.status.cert_hash().as_bytes()))
    }
}

pub(crate) fn certificate_hash(
    certificate: &CmpCertificate,
    algorithm: &AlgorithmIdentifier,
    digests: &dyn DigestProvider,
) -> Result<Vec<u8>, CmpError> {
    if !matches!(algorithm.parameters(), None | Some(Asn1Object::Null(_))) {
        return Err(CmpError::Invalid("unsupported certConf digest parameters"));
    }
    let encoded = certificate.encode_to_vec(&EncodingOptions::DER)?;
    Ok(digests.calculate_by_oid(algorithm.algorithm(), &encoded)?)
}
