use crate::{EntryBase, KeyPairGenerator};

pub trait KeyPairGeneratorEntry: EntryBase {
    fn create(&self) -> Box<dyn KeyPairGenerator>;
}
