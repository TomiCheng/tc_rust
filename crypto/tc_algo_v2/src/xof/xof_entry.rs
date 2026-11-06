use crate::{EntryBase, Xof};

pub trait XofEntry: EntryBase {
    fn create(&self) -> Box<dyn Xof>;
}
