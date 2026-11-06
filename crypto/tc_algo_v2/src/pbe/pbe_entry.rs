use crate::EntryBase;
use crate::pbe::Pbe;

pub trait PbeEntry: EntryBase {
    fn create(&self) -> Box<dyn Pbe>;
}
