use crate::EntryBase;
use crate::cipher::Cipher;

pub trait CipherEntry: EntryBase {
    fn create(&self) -> Box<dyn Cipher>;
}
