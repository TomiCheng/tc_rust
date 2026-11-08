use crate::EntryBase;
use crate::drbg::Drbg;

pub trait DrbgEntry: EntryBase {
    // A new generator, already seeded
    fn create(&self) -> Box<dyn Drbg>;
}
