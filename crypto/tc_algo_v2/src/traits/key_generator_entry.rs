use super::{EntryBase, KeyGenerator};

pub trait KeyGeneratorEntry: EntryBase {
    fn create(&self) -> Box<dyn KeyGenerator>;
}
