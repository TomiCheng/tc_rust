use core::iter;

use tc_asn1::Asn1Oid;

use crate::drbg::{Drbg, DrbgEntry, DrbgProvider};
use crate::{AlgoError, ErrorKind};

pub(crate) struct EmptyDrbgProvider;

impl DrbgProvider for EmptyDrbgProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DrbgEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn Drbg>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownDrbg))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Drbg>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownDrbg))
    }
}
