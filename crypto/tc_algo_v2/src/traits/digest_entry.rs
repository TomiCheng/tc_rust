use super::{Digest, EntryBase};

pub trait DigestEntry: EntryBase {
    fn create(&self) -> Box<dyn Digest>;
}
