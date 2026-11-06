use crate::{AlgoError, Params};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapDirection {
    Wrap,
    Unwrap,
}

pub trait Wrapper {
    fn init(&mut self, direction: WrapDirection, params: &dyn Params) -> Result<(), AlgoError>;

    fn wrap(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError>;

    fn unwrap(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError>;
}
