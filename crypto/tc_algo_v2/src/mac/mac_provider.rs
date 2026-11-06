use tc_asn1::Asn1Oid;

use crate::mac::{Mac, MacEntry};
use crate::{AlgoError, Params};

pub trait MacProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn MacEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Mac>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Mac>, AlgoError>;

    fn calculate_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        let mut mac = self.get_by_name(name)?;
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
        let mut mac = self.get_by_oid(oid)?;
        mac.init(params)?;
        mac.update(input)?;
        mac.finalize()
    }

    // A wrong tag is Ok(false), so the caller has to look at the answer
    fn verify_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        input: &[u8],
        tag: &[u8],
    ) -> Result<bool, AlgoError> {
        let mut mac = self.get_by_name(name)?;
        mac.init(params)?;
        mac.update(input)?;
        mac.verify(tag)
    }

    // A wrong tag is Ok(false), so the caller has to look at the answer
    fn verify_by_oid(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        input: &[u8],
        tag: &[u8],
    ) -> Result<bool, AlgoError> {
        let mut mac = self.get_by_oid(oid)?;
        mac.init(params)?;
        mac.update(input)?;
        mac.verify(tag)
    }
}
