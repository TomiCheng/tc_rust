use super::EntryBase;

pub trait Policy {
    fn filter(&self, entry: &dyn EntryBase) -> bool;
}
