use super::{EntryBase, KeyPairGenerator};

pub trait KeyPairGeneratorEntry: EntryBase {
    fn create(&self) -> Box<dyn KeyPairGenerator>;
}
