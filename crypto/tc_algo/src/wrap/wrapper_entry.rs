use crate::EntryBase;
use crate::wrap::Wrapper;

pub trait WrapperEntry: EntryBase {
    fn create(&self) -> Box<dyn Wrapper>;
}
