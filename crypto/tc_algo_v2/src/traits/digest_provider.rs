use super::DigestEntry;

pub trait DigestProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DigestEntry> + '_>;
}
