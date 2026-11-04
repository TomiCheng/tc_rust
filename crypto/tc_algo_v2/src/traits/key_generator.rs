use super::Params;
use crate::AlgoError;

pub trait KeyGenerator {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError>;

    // The key is itself the params of what takes it
    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError>;
}
