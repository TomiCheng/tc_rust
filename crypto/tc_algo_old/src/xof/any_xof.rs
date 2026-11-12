use core::fmt;

use super::entry::BoxedXof;
use super::{AnyXofParams, XofEntry};
use crate::{AlgoError, ErrorKind};

pub struct AnyXof {
    entry: &'static XofEntry,
    // None until init for an XOF that cannot start without its params, such as ParallelHash
    xof: Option<BoxedXof>,
    squeezing: bool,
}

impl AnyXof {
    pub(super) fn new(entry: &'static XofEntry) -> Self {
        Self {
            entry,
            xof: entry.create_default(),
            squeezing: false,
        }
    }

    pub fn entry(&self) -> &'static XofEntry {
        self.entry
    }

    // Starts a new message under these params. Refused params go back to what a new XOF does, so
    // that it never goes on under the earlier ones
    pub fn init(&mut self, params: &AnyXofParams) -> Result<(), AlgoError> {
        self.squeezing = false;
        match self.entry.create(params) {
            Ok(xof) => {
                self.xof = Some(xof);
                Ok(())
            }
            Err(error) => {
                self.xof = self.entry.create_default();
                Err(error)
            }
        }
    }

    // Each call to TupleHash is one element of its tuple; for the others only the bytes matter
    pub fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        if self.squeezing {
            return Err(AlgoError::new(ErrorKind::XofOutputStarted));
        }
        self.xof()?.update(input);
        Ok(())
    }

    // Fills `output` with the next bytes and stays ready for more; update is refused from here on,
    // until finalize, reset or init starts a new message
    pub fn output(&mut self, output: &mut [u8]) -> Result<(), AlgoError> {
        self.xof()?.output(output);
        self.squeezing = true;
        Ok(())
    }

    // The next `len` bytes, after which the XOF starts the next message under the same params
    pub fn finalize(&mut self, len: usize) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; len];
        self.xof()?.output_final(&mut output);
        self.squeezing = false;
        Ok(output)
    }

    pub fn reset(&mut self) {
        if let Some(xof) = &mut self.xof {
            xof.reset();
        }
        self.squeezing = false;
    }

    fn xof(&mut self) -> Result<&mut BoxedXof, AlgoError> {
        self.xof
            .as_mut()
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))
    }
}

// Shows only the XOF's name, never its internal state
impl fmt::Debug for AnyXof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyXof")
            .field("name", &self.entry.name())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AnyXof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.entry.name())
    }
}
