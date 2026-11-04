#[cfg(feature = "hmac")]
use core::error::Error;

#[cfg(feature = "hmac")]
use tc_macs::{KeyRef, Mac, MacInit};

use super::AnyMacParams;
#[cfg(feature = "hmac")]
use super::classify::{Classify, to_algo_error};
use crate::AlgoError;

// The MAC behind an AnyMac. The entry has already checked the operation fields; each implementation
// checks that their contents suit it, and is Send so AnyMac can move between threads
pub(super) trait DynMac: Send {
    fn init(&mut self, params: &AnyMacParams) -> Result<(), AlgoError>;

    fn mac_size(&self) -> usize;

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError>;

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError>;

    fn reset(&mut self);
}

// A concrete MAC that takes a key and nothing else, with its errors turned into AlgoError
#[cfg(feature = "hmac")]
pub(super) struct KeyMac<T>(pub(super) T);

#[cfg(feature = "hmac")]
impl<T> DynMac for KeyMac<T>
where
    T: Mac + for<'a> MacInit<KeyRef<'a>> + Send,
    <T as Mac>::Error: Classify + Error + Send + Sync + 'static,
    for<'a> <T as MacInit<KeyRef<'a>>>::Error: Classify + Error + Send + Sync + 'static,
{
    fn init(&mut self, params: &AnyMacParams) -> Result<(), AlgoError> {
        self.0
            .init(&KeyRef::new(&params.key().key))
            .map_err(to_algo_error)
    }

    fn mac_size(&self) -> usize {
        self.0.mac_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.0.update(input).map_err(to_algo_error)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.do_final(output).map_err(to_algo_error)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}
