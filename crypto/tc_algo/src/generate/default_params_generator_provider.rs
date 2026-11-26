use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::generate::{ParamsGenerator, ParamsGeneratorEntry, ParamsGeneratorProvider};
use crate::{AlgoError, ErrorKind};

impl ParamsGeneratorProvider for DefaultProvider<dyn ParamsGeneratorEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn ParamsGeneratorEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn ParamsGeneratorEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn ParamsGenerator>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownParamsGenerator))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn ParamsGenerator>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownParamsGenerator))
    }
}
