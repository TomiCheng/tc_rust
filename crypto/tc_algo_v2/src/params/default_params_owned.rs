use crate::Params;

pub struct DefaultParamsOwned {}

impl Params for DefaultParamsOwned {
    fn as_bytes(&self) -> &[u8] {
        todo!()
    }
}
