use crate::CipherBuilder;

pub trait CipherBuilderWithKey: CipherBuilder {
    fn key(&self) -> &[u8];
}
