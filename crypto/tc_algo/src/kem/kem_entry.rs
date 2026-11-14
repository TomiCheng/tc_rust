use crate::EntryBase;
use crate::kem::{Decapsulator, Encapsulator};

// One row of KemUtilities, which gives both sides of its KEM
pub trait KemEntry: EntryBase {
    fn create_encapsulator(&self) -> Box<dyn Encapsulator>;

    fn create_decapsulator(&self) -> Box<dyn Decapsulator>;
}
