use crate::EntryBase;
use crate::generate::KeyGenerator;

pub trait KeyGeneratorEntry: EntryBase {
    fn create(&self) -> Box<dyn KeyGenerator>;
}
