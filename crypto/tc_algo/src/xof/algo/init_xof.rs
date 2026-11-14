use tc_digest::{TryDigest, TryXof};

use super::row::TcXof;
use crate::digest::Digest;
use crate::xof::Xof;
use crate::{AlgoError, ErrorKind, Params};

// An XOF that init sets, by building it again from params of type P: init starts a new message,
// and reset keeps what init set
pub(super) struct InitXof<D, P> {
    xof: TcXof<D>,
    init: fn(&P) -> Result<D, AlgoError>,
}

impl<D, P> InitXof<D, P> {
    pub(super) fn new(xof: D, init: fn(&P) -> Result<D, AlgoError>) -> Self {
        Self {
            xof: TcXof(xof),
            init,
        }
    }
}

impl<D: tc_digest::Xof, P> TryDigest for InitXof<D, P> {
    type Error = AlgoError;

    fn digest_size(&self) -> usize {
        self.xof.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.xof.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.xof.try_update(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.xof.try_do_final(output)
    }

    fn try_reset(&mut self) -> Result<(), AlgoError> {
        self.xof.try_reset()
    }
}

impl<D: tc_digest::Xof, P> TryXof for InitXof<D, P> {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.xof.try_output(output)
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.xof.try_output_final(output)
    }
}

impl<D: tc_digest::Xof, P> Digest for InitXof<D, P> {}

impl<D: tc_digest::Xof, P: 'static> Xof for InitXof<D, P> {
    // Params of another type, or that the XOF refuses, are InvalidParams and change nothing
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<P>()
            .ok_or_else(|| AlgoError::new(ErrorKind::InvalidParams))?;
        self.xof = TcXof((self.init)(params)?);
        Ok(())
    }
}

// The error init gives for params the XOF refuses
#[cfg(any(
    feature = "parallelhash128",
    feature = "parallelhash256",
    feature = "ascon-cxof128",
    feature = "blake2xs",
    feature = "blake3",
))]
pub(super) fn invalid() -> AlgoError {
    AlgoError::new(ErrorKind::InvalidParams)
}
