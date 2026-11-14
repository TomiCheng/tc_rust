use crate::digest::Digest;
use crate::traits::EntryBase;

pub trait DigestEntry: EntryBase {
    fn create(&self) -> Box<dyn Digest>;
}
