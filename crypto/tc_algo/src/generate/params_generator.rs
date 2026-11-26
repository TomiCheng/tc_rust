use crate::{AlgoError, ErrorKind, Params};

pub trait ParamsGenerator {
    // Optional: generate works with the row's defaults without it. One with nothing to set refuses
    // any params
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        Err(AlgoError::new(ErrorKind::InvalidParams))
    }

    // The params are those of what takes them, as a group is of a key pair generator
    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError>;
}
