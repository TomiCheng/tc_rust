use core::fmt;

use tc_key_wrap::WrapDirection;

use super::dyn_wrapper::DynWrapper;
use super::{AnyWrapParams, WrapEntry};
use crate::AlgoError;
use crate::params::SecretKey;

pub struct AnyWrapper {
    entry: &'static WrapEntry,
    wrapper: Box<dyn DynWrapper>,
}

impl AnyWrapper {
    pub(super) fn new(entry: &'static WrapEntry) -> Self {
        Self {
            entry,
            wrapper: entry.create(),
        }
    }

    pub fn entry(&self) -> &'static WrapEntry {
        self.entry
    }

    // Each direction takes its own init. Refused params go back to a new wrapper, so that it never
    // goes on under the earlier key
    pub fn init(
        &mut self,
        direction: WrapDirection,
        params: &AnyWrapParams,
    ) -> Result<(), AlgoError> {
        if let Err(error) = self.entry.check(params) {
            self.wrapper = self.entry.create();
            return Err(error);
        }
        self.wrapper.init(direction, &params.key().key, params.iv())
    }

    pub fn wrap_key(&mut self, key: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.wrapper.wrapped_len(key.len())?];
        let written = self.wrapper.wrap_into(key, &mut output)?;
        output.truncate(written);
        Ok(output)
    }

    // Comes back as a SecretKey from the start, so that what it held is wiped on any error too
    pub fn unwrap_key(&mut self, wrapped: &[u8]) -> Result<SecretKey, AlgoError> {
        let len = self.wrapper.max_unwrapped_len(wrapped.len())?;
        let mut key = SecretKey::new(vec![0; len]);
        let written = self.wrapper.unwrap_into(wrapped, &mut key.key)?;
        key.key.truncate(written);
        Ok(key)
    }
}

// Shows the wrapper's name, never its key
impl fmt::Debug for AnyWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyWrapper")
            .field("name", &self.entry.name())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AnyWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.entry.name())
    }
}
