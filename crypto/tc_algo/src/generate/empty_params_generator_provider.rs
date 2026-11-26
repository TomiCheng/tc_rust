use core::iter;

use tc_asn1::Asn1Oid;

use crate::generate::{ParamsGenerator, ParamsGeneratorEntry, ParamsGeneratorProvider};
use crate::{AlgoError, ErrorKind};

pub(crate) struct EmptyParamsGeneratorProvider;

impl ParamsGeneratorProvider for EmptyParamsGeneratorProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn ParamsGeneratorEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn ParamsGenerator>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownParamsGenerator))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn ParamsGenerator>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownParamsGenerator))
    }
}
