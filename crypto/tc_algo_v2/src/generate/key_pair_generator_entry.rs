use crate::EntryBase;
use crate::generate::KeyPairGenerator;

pub trait KeyPairGeneratorEntry: EntryBase {
    fn create(&self) -> Box<dyn KeyPairGenerator>;
}
