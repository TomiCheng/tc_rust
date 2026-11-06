use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::signer::{Signer, SignerEntry, SignerProvider};
use crate::{AlgoError, ErrorKind};

impl SignerProvider for DefaultProvider<dyn SignerEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn SignerEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn SignerEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Signer>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownSigner))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Signer>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownSigner))
    }
}
