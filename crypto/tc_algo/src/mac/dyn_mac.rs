use core::error::Error;

use tc_macs::{Mac, MacInit};

use super::AnyMacParams;
use super::init_params::MacParams;
use crate::AlgoError;
use crate::cipher::classify::{Classify, to_algo_error};

// The MAC behind an AnyMac. The entry has already checked the operation fields; each implementation
// checks that their contents suit it, and is Send so AnyMac can move between threads
pub(super) trait DynMac: Send {
    fn init(&mut self, params: &AnyMacParams) -> Result<(), AlgoError>;

    fn mac_size(&self) -> usize;

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError>;

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError>;

    fn reset(&mut self);
}

// A concrete MAC with its errors turned into AlgoError
pub(super) struct Mapped<T> {
    mac: T,
    // The bytes of zeros that stand for an IV the caller left out, as a MAC of Bouncy Castle keyed
    // without an IV starts from a zero block
    zero_iv: usize,
}

impl<T> Mapped<T> {
    #[allow(dead_code, reason = "unused when every MAC that takes an IV is off")]
    pub(super) fn new(mac: T, zero_iv: usize) -> Self {
        Self { mac, zero_iv }
    }

    #[allow(dead_code, reason = "unused when every MAC feature is off")]
    pub(super) fn key_only(mac: T) -> Self {
        Self::new(mac, 0)
    }
}

impl<T> DynMac for Mapped<T>
where
    T: Mac + for<'a> MacInit<MacParams<'a>> + Send,
    <T as Mac>::Error: Classify + Error + Send + Sync + 'static,
    for<'a> <T as MacInit<MacParams<'a>>>::Error: Classify + Error + Send + Sync + 'static,
{
    fn init(&mut self, params: &AnyMacParams) -> Result<(), AlgoError> {
        let zeros = vec![0; self.zero_iv];
        self.mac
            .init(&MacParams {
                key: &params.key().key,
                iv: params.iv().unwrap_or(&zeros),
            })
            .map_err(to_algo_error)
    }

    fn mac_size(&self) -> usize {
        self.mac.mac_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.mac.update(input).map_err(to_algo_error)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.mac.do_final(output).map_err(to_algo_error)
    }

    fn reset(&mut self) {
        self.mac.reset();
    }
}
