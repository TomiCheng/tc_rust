use super::{AnyKeyParams, AnyOpParams};

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AnyParams {
    pub key: AnyKeyParams,
    pub op: AnyOpParams,
}

impl AnyParams {
    // #[non_exhaustive] keeps other crates from writing the struct out, so this is the way in;
    // the operation fields start empty and are set one by one
    pub fn new(key: AnyKeyParams) -> Self {
        Self {
            key,
            op: AnyOpParams::default(),
        }
    }
}
