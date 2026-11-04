use super::DigestFactory;

pub trait Algo {
    fn digest(&self) -> &dyn DigestFactory;
}
