use std::io;

use tc_buffered_cipher::BufferedCipher;

use crate::CipherWriter;

pub struct BufferedCipherWriter<C, W> {
    cipher: C,
    output: W,
}

impl<C: BufferedCipher, W: io::Write> BufferedCipherWriter<C, W> {
    pub fn new(cipher: C, output: W) -> Self {
        Self { cipher, output }
    }
}

impl<C, W> io::Write for BufferedCipherWriter<C, W>
where
    C: BufferedCipher,
    C::Error: Send + Sync + 'static,
    W: io::Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self
            .cipher
            .update_output_len(buf.len())
            .map_err(io::Error::other)?;
        let mut out = vec![0; len];
        let written = self
            .cipher
            .process_bytes(buf, &mut out)
            .map_err(io::Error::other)?;
        self.output.write_all(&out[..written])?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

impl<C, W> CipherWriter<W> for BufferedCipherWriter<C, W>
where
    C: BufferedCipher,
    C::Error: Send + Sync + 'static,
    W: io::Write,
{
    type Error = io::Error;

    fn finish(mut self) -> io::Result<W> {
        let len = self.cipher.output_len(0).map_err(io::Error::other)?;
        let mut out = vec![0; len];
        let written = self.cipher.do_final(&mut out).map_err(io::Error::other)?;
        self.output.write_all(&out[..written])?;
        self.output.flush()?;
        Ok(self.output)
    }
}
