use super::EntryBase;

pub trait Policy: Send + Sync {
    fn filter(&self, entry: &dyn EntryBase) -> bool;
}
