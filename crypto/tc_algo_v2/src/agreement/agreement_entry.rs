use crate::EntryBase;
use crate::agreement::Agreement;

pub trait AgreementEntry: EntryBase {
    fn create(&self) -> Box<dyn Agreement>;
}
