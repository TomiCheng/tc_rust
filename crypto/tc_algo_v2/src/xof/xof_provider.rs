use tc_asn1::Asn1Oid;

use crate::{AlgoError, ErrorKind, Params, Xof, XofEntry};

pub trait XofProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn XofEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Xof>>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Xof>>;

    fn calculate_by_name(
        &self,
        name: &str,
        input: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, AlgoError> {
        calculate(self.get_by_name(name), None, input, len)
    }

    fn calculate_by_oid(
        &self,
        oid: &Asn1Oid,
        input: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, AlgoError> {
        calculate(self.get_by_oid(oid), None, input, len)
    }

    fn calculate_by_name_with(
        &self,
        name: &str,
        params: &dyn Params,
        input: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, AlgoError> {
        calculate(self.get_by_name(name), Some(params), input, len)
    }

    fn calculate_by_oid_with(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        input: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, AlgoError> {
        calculate(self.get_by_oid(oid), Some(params), input, len)
    }
}

fn calculate(
    xof: Option<Box<dyn Xof>>,
    params: Option<&dyn Params>,
    input: &[u8],
    len: usize,
) -> Result<Vec<u8>, AlgoError> {
    let mut xof = xof.ok_or(AlgoError::new(ErrorKind::UnknownXof))?;
    if let Some(params) = params {
        xof.init(params)?;
    }
    xof.update(input)?;
    xof.finalize(len)
}
