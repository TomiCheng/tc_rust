use tc_asn1::Asn1Oid;

use crate::agreement::{Agreement, AgreementEntry, AgreementProvider};
use crate::default_provider::DefaultProvider;
use crate::{AlgoError, ErrorKind};

impl AgreementProvider for DefaultProvider<dyn AgreementEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn AgreementEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn AgreementEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Agreement>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownAgreement))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Agreement>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownAgreement))
    }
}
