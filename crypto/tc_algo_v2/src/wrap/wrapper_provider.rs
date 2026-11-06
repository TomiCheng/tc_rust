use tc_asn1::Asn1Oid;

use crate::{AlgoError, Params, WrapDirection, Wrapper, WrapperEntry};

pub trait WrapperProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn WrapperEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Wrapper>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Wrapper>, AlgoError>;

    fn wrap_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        wrap(self.get_by_name(name)?, params, input)
    }

    fn wrap_by_oid(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        wrap(self.get_by_oid(oid)?, params, input)
    }

    fn unwrap_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        unwrap(self.get_by_name(name)?, params, input)
    }

    fn unwrap_by_oid(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        unwrap(self.get_by_oid(oid)?, params, input)
    }
}

fn wrap(
    mut wrapper: Box<dyn Wrapper>,
    params: &dyn Params,
    input: &[u8],
) -> Result<Vec<u8>, AlgoError> {
    wrapper.init(WrapDirection::Wrap, params)?;
    wrapper.wrap(input)
}

fn unwrap(
    mut wrapper: Box<dyn Wrapper>,
    params: &dyn Params,
    input: &[u8],
) -> Result<Vec<u8>, AlgoError> {
    wrapper.init(WrapDirection::Unwrap, params)?;
    wrapper.unwrap(input)
}
