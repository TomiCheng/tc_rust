use std::io;

/// Iterates over a raw OpenPGP signature subpacket block.
pub(super) struct Subpackets<'a>(&'a [u8]);

impl<'a> Subpackets<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    fn read(&mut self) -> io::Result<(u8, &'a [u8])> {
        let first = self.take(1)?[0];
        let size = match first {
            0..=191 => usize::from(first),
            192..=254 => ((usize::from(first) - 192) << 8) + usize::from(self.take(1)?[0]) + 192,
            255 => {
                let bytes = self.take(4)?.try_into().map_err(|_| invalid())?;
                usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| invalid())?
            }
        };
        let (&tag, value) = self.take(size)?.split_first().ok_or_else(invalid)?;
        Ok((tag, value))
    }

    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let (field, rest) = self.0.split_at_checked(len).ok_or_else(invalid)?;
        self.0 = rest;
        Ok(field)
    }
}

impl<'a> Iterator for Subpackets<'a> {
    type Item = io::Result<(u8, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        let item = self.read();
        if item.is_err() {
            self.0 = &[];
        }
        Some(item)
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed signature subpacket")
}
