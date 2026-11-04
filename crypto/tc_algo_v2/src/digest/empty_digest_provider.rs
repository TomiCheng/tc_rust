use core::iter;

use crate::{DigestEntry, DigestProvider};

pub(crate) struct EmptyDigestProvider;

impl DigestProvider for EmptyDigestProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DigestEntry> + '_> {
        Box::new(iter::empty())
    }
}
