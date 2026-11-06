use crate::EntryBase;
use crate::xof::Xof;

pub trait XofEntry: EntryBase {
    fn create(&self) -> Box<dyn Xof>;
}
