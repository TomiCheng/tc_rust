use crate::EntryBase;
use crate::mac::Mac;

pub trait MacEntry: EntryBase {
    fn create(&self) -> Box<dyn Mac>;
}
