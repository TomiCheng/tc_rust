use core::iter;

use tc_asn1::Asn1Oid;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::agreement::{Agreement, AgreementEntry, AgreementProvider};
use crate::{AlgoError, ErrorKind};

pub(crate) struct EmptyAgreementProvider;

impl AgreementProvider for EmptyAgreementProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn AgreementEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn Agreement>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownAgreement))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Agreement>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownAgreement))
    }

    fn get_with_kdf_by_name(
        &self,
        _name: &str,
        _wrap: &AlgorithmIdentifier,
    ) -> Result<Box<dyn Agreement>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownAgreement))
    }

    fn get_with_kdf_by_oid(
        &self,
        _oid: &Asn1Oid,
        _wrap: &AlgorithmIdentifier,
    ) -> Result<Box<dyn Agreement>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownAgreement))
    }
}
