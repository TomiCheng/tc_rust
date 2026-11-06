use crate::EntryBase;
use crate::kem::Kem;

pub trait KemEntry: EntryBase {
    fn create(&self) -> Box<dyn Kem>;
}
