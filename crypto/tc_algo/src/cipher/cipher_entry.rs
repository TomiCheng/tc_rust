use crate::EntryBase;
use crate::cipher::Cipher;

pub trait CipherEntry: EntryBase {
    fn create(&self) -> Box<dyn Cipher>;

    // The cipher of `name`, which matches_name took: by default the one cipher of the row. A row
    // whose names take a value, as `AES/CFB8/NOPADDING` does, reads it from the name
    fn create_by_name(&self, _name: &str) -> Box<dyn Cipher> {
        self.create()
    }
}
