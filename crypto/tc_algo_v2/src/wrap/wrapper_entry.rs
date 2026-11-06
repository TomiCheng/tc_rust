use crate::{EntryBase, Wrapper};

pub trait WrapperEntry: EntryBase {
    fn create(&self) -> Box<dyn Wrapper>;
}
