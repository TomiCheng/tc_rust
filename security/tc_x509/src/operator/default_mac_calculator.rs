use std::io;

use tc_algo_v2::mac::Mac;

use crate::operator::{BlockResult, DefaultMacResult, StreamCalculator};

// BC's DefaultMacCalculator: what is written goes into the MAC, which must be initialized with a
// key. A failure of the MAC comes out of write as an io::Error, with the AlgoError as its inner
// error
pub struct DefaultMacCalculator {
    mac: Box<dyn Mac>,
}

impl DefaultMacCalculator {
    pub fn new(mac: Box<dyn Mac>) -> Self {
        Self { mac }
    }
}

impl io::Write for DefaultMacCalculator {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.mac.update(buf).map_err(io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl StreamCalculator<Box<dyn BlockResult>> for DefaultMacCalculator {
    fn result(self: Box<Self>) -> Box<dyn BlockResult> {
        Box::new(DefaultMacResult::new(self.mac))
    }
}
