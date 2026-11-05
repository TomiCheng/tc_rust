use crate::{AlgoError, ErrorKind, Params};

pub trait KeyGenerator {
    // Optional: generate works without it. One with nothing to set refuses any params
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        Err(AlgoError::new(ErrorKind::InvalidParams))
    }

    // The key is itself the params of what takes it
    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError>;
}
