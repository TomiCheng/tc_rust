use crate::EntryBase;
use crate::generate::ParamsGenerator;

pub trait ParamsGeneratorEntry: EntryBase {
    fn create(&self) -> Box<dyn ParamsGenerator>;
}
