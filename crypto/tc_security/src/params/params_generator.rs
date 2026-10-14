use super::{AnyParams, ParamGenParams};
use crate::SecurityError;

pub struct ParamsGenerator {}

impl ParamsGenerator {
    pub fn init(&mut self, params: &ParamGenParams) -> Result<(), SecurityError> {
        todo!("{params:?}")
    }

    pub fn generate(&mut self) -> Result<AnyParams, SecurityError> {
        todo!()
    }
}
