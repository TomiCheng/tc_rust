use crate::Params;

pub struct DefaultParamsRef<'a>(&'a [u8]);

impl Params for DefaultParamsRef<'_> {
    fn as_bytes(&self) -> &[u8] {
        self.0
    }
}
