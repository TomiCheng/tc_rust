use core::iter;

use tc_asn1::Asn1Oid;

use crate::kdf::{Kdf, KdfEntry, KdfProvider};
use crate::{AlgoError, ErrorKind};

pub(crate) struct EmptyKdfProvider;

impl KdfProvider for EmptyKdfProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KdfEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn Kdf>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownKdf))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Kdf>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownKdf))
    }
}
