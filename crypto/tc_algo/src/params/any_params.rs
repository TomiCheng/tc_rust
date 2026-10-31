use super::{AnyKeyParams, AnyOpParams};

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AnyParams {
    pub key: AnyKeyParams,
    pub op: AnyOpParams,
}
