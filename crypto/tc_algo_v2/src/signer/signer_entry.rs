use crate::EntryBase;
use crate::signer::Signer;

pub trait SignerEntry: EntryBase {
    fn create(&self) -> Box<dyn Signer>;
}
