use crate::KeyParams;

pub struct KeyRef<'a> {
    key: &'a [u8],
}

impl<'a> KeyRef<'a> {
    pub const fn new(key: &'a [u8]) -> Self {
        Self { key }
    }
}

impl KeyParams for KeyRef<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}
