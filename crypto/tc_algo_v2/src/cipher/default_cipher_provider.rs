use tc_asn1::Asn1Oid;

use crate::cipher::{Cipher, CipherEntry, CipherProvider};
use crate::default_provider::DefaultProvider;
use crate::{AlgoError, ErrorKind};

impl CipherProvider for DefaultProvider<dyn CipherEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn CipherEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn CipherEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Cipher>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownCipher))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Cipher>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownCipher))
    }
}
