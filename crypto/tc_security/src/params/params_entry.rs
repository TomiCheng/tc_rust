use super::{AnyParams, ParamsGenerator};

pub struct ParamsEntry {}

impl ParamsEntry {
    pub fn generator(&self, _key: AnyParams) -> ParamsGenerator {
        todo!()
    }
}
