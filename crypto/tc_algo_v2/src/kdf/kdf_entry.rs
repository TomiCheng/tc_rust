use crate::EntryBase;
use crate::kdf::Kdf;

pub trait KdfEntry: EntryBase {
    fn create(&self) -> Box<dyn Kdf>;
}
