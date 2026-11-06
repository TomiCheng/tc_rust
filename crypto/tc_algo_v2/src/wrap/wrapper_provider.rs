use tc_asn1::Asn1Oid;

use crate::{AlgoError, ErrorKind, Params, WrapDirection, Wrapper, WrapperEntry};

pub trait WrapperProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn WrapperEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Wrapper>>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Wrapper>>;

    fn wrap_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        wrap(self.get_by_name(name), params, input)
    }

    fn wrap_by_oid(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        wrap(self.get_by_oid(oid), params, input)
    }

    fn unwrap_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        unwrap(self.get_by_name(name), params, input)
    }

    fn unwrap_by_oid(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        unwrap(self.get_by_oid(oid), params, input)
    }
}

fn wrap(
    wrapper: Option<Box<dyn Wrapper>>,
    params: &dyn Params,
    input: &[u8],
) -> Result<Vec<u8>, AlgoError> {
    let mut wrapper = wrapper.ok_or(AlgoError::new(ErrorKind::UnknownWrapper))?;
    wrapper.init(WrapDirection::Wrap, params)?;
    wrapper.wrap(input)
}

fn unwrap(
    wrapper: Option<Box<dyn Wrapper>>,
    params: &dyn Params,
    input: &[u8],
) -> Result<Vec<u8>, AlgoError> {
    let mut wrapper = wrapper.ok_or(AlgoError::new(ErrorKind::UnknownWrapper))?;
    wrapper.init(WrapDirection::Unwrap, params)?;
    wrapper.unwrap(input)
}
