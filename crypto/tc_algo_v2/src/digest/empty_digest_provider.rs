use core::iter;

use tc_asn1::Asn1Oid;

use crate::digest::{Digest, DigestEntry, DigestProvider};
use crate::{AlgoError, ErrorKind};

pub(crate) struct EmptyDigestProvider;

impl DigestProvider for EmptyDigestProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DigestEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn Digest>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownDigest))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Digest>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownDigest))
    }
}
