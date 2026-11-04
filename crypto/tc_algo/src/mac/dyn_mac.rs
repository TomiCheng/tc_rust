use super::AnyMacParams;
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
