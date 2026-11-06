use core::iter;

use tc_asn1::Asn1Oid;

use crate::cipher::{Cipher, CipherEntry, CipherProvider};
use crate::{AlgoError, ErrorKind};

pub(crate) struct EmptyCipherProvider;

impl CipherProvider for EmptyCipherProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn CipherEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn Cipher>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownCipher))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Cipher>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownCipher))
    }
}
