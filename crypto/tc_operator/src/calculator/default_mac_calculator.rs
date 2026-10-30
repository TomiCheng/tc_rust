use std::io;

use tc_macs::Mac;

use crate::MacCalculator;

pub struct DefaultMacCalculator<M> {
    mac: M,
}

impl<M: Mac> DefaultMacCalculator<M> {
    pub fn new(mac: M) -> Self {
        Self { mac }
    }
}

impl<M> io::Write for DefaultMacCalculator<M>
where
    M: Mac,
    M::Error: Send + Sync + 'static,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.mac.update(buf).map_err(io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<M> MacCalculator for DefaultMacCalculator<M>
where
    M: Mac,
    M::Error: Send + Sync + 'static,
{
    type Error = M::Error;

    fn finish(mut self) -> Result<Vec<u8>, M::Error> {
        let mut output = vec![0; self.mac.mac_size()];
        let len = self.mac.do_final(&mut output)?;
        output.truncate(len);
        Ok(output)
    }
}
