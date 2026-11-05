use super::{Cipher, EntryBase};

pub trait CipherEntry: EntryBase {
    fn create(&self) -> Box<dyn Cipher>;
}
