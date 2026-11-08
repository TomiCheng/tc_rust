use tc_algo_v2::mac::Mac;

use crate::X509Error;
use crate::operator::BlockResult;

// BC's DefaultMacResult: the tag of what was written into the MAC. The MAC then starts the next
// message, so collect the result once
pub struct DefaultMacResult {
    mac: Box<dyn Mac>,
}

impl DefaultMacResult {
    pub fn new(mac: Box<dyn Mac>) -> Self {
        Self { mac }
    }
}

impl BlockResult for DefaultMacResult {
    fn max_result_length(&self) -> usize {
        self.mac.mac_size()
    }

    fn collect_into(&mut self, output: &mut [u8]) -> Result<usize, X509Error> {
        Ok(self.mac.do_final(output)?)
    }
}
