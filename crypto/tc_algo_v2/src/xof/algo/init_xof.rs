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

impl<D: tc_digest::Xof, P> Digest for InitXof<D, P> {
    fn digest_size(&self) -> usize {
        self.xof.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.xof.byte_length()
    }

    fn update(&mut self, input: &[u8]) {
        self.xof.update(input);
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.xof.do_final(output)
    }

    fn reset(&mut self) {
        self.xof.reset();
    }
}

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

    fn output(&mut self, output: &mut [u8]) -> usize {
        self.xof.output(output)
    }

    fn output_final(&mut self, output: &mut [u8]) -> usize {
        self.xof.output_final(output)
    }
}

// The error init gives for params the XOF refuses
#[cfg(any(feature = "ascon-cxof128", feature = "blake2xs", feature = "blake3"))]
pub(super) fn invalid() -> AlgoError {
    AlgoError::new(ErrorKind::InvalidParams)
}
