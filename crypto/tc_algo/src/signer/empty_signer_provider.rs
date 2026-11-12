use core::iter;

use tc_asn1::Asn1Oid;

use crate::signer::{Signer, SignerEntry, SignerProvider};
use crate::{AlgoError, ErrorKind};

pub(crate) struct EmptySignerProvider;

impl SignerProvider for EmptySignerProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn SignerEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn Signer>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownSigner))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Signer>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownSigner))
    }
}
