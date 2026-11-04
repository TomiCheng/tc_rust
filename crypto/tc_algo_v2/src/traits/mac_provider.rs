use tc_asn1::Asn1Oid;

use super::{Mac, MacEntry, Params};
use crate::{AlgoError, ErrorKind};

pub trait MacProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn MacEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Mac>>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Mac>>;

    fn calculate_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        let mut mac = self
            .get_by_name(name)
            .ok_or(AlgoError::new(ErrorKind::UnknownMac))?;
        mac.init(params)?;
        mac.update(input)?;
        mac.finalize()
    }

    fn calculate_by_oid(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        let mut mac = self
            .get_by_oid(oid)
            .ok_or(AlgoError::new(ErrorKind::UnknownMac))?;
        mac.init(params)?;
        mac.update(input)?;
        mac.finalize()
    }
}
