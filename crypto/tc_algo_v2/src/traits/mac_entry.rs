use super::{EntryBase, Mac};

pub trait MacEntry: EntryBase {
    fn create(&self) -> Box<dyn Mac>;
}
