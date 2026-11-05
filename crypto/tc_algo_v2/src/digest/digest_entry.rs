use crate::traits::EntryBase;
use crate::digest::Digest;

pub trait DigestEntry: EntryBase {
    fn create(&self) -> Box<dyn Digest>;
}
