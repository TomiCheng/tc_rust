use std::io::{self, Write};

use crate::{BodyLength, PacketHeaderFormat, PacketTag};

/// Writes OpenPGP packets.
pub struct PgpWriter<W> {
    inner: W,
    ready: bool,
}

impl<W: Write> PgpWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, ready: true }
    }

    /// Starts a packet with current OpenPGP framing. Partial lengths specify a chunk size in bytes.
    /// Finish the returned body before starting another packet.
    pub fn write_body(
        &mut self,
        tag: PacketTag,
        length: BodyLength,
    ) -> io::Result<PgpBodyWriter<'_, W>> {
        let (body, _) = self.write_body_with_format(tag, length, PacketHeaderFormat::OpenPgp)?;
        Ok(body)
    }

    pub(crate) fn write_body_with_format(
        &mut self,
        tag: PacketTag,
        length: BodyLength,
        header_format: PacketHeaderFormat,
    ) -> io::Result<(PgpBodyWriter<'_, W>, u64)> {
        if !self.ready {
            return Err(io::Error::other("previous packet was not completed"));
        }
        let id = u8::from(tag);
        let max_tag = match header_format {
            PacketHeaderFormat::OpenPgp => 63,
            PacketHeaderFormat::Legacy => 15,
        };
        if !(1..=max_tag).contains(&id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid packet tag",
            ));
        }
        let mode = match length {
            BodyLength::Fixed(n) => Mode::Fixed { remaining: n },
            BodyLength::Partial(n)
                if matches!(id, 8 | 9 | 11 | 18)
                    && n.is_power_of_two()
                    && (512..=1 << 30).contains(&n) =>
            {
                Mode::Partial {
                    size: n as usize,
                    pending: Vec::new(),
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported body length for this tag",
                ));
            }
        };
        let mut length_bytes = [0; 5];
        let (tag_byte, encoded_length) = match (header_format, &mode) {
            (PacketHeaderFormat::OpenPgp, Mode::Fixed { remaining }) => {
                (0xc0 | id, encode_length(*remaining, &mut length_bytes))
            }
            (PacketHeaderFormat::OpenPgp, Mode::Partial { .. }) => (0xc0 | id, &[][..]),
            (PacketHeaderFormat::Legacy, Mode::Fixed { remaining }) => {
                let (length_type, width) = match remaining {
                    0..=0xff => (0, 1),
                    0x100..=0xffff => (1, 2),
                    _ => (2, 4),
                };
                length_bytes[..4].copy_from_slice(&remaining.to_be_bytes());
                (0x80 | (id << 2) | length_type, &length_bytes[4 - width..4])
            }
            (PacketHeaderFormat::Legacy, Mode::Partial { .. }) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "legacy packet framing requires a definite body length",
                ));
            }
        };

        self.ready = false;
        self.inner.write_all(&[tag_byte])?;
        self.inner.write_all(encoded_length)?;
        Ok((
            PgpBodyWriter {
                parent: self,
                mode,
                failed: false,
            },
            1 + encoded_length.len() as u64,
        ))
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

fn write_length(out: &mut impl Write, n: u32) -> io::Result<()> {
    out.write_all(encode_length(n, &mut [0; 5]))
}

fn encode_length(n: u32, bytes: &mut [u8; 5]) -> &[u8] {
    match n {
        0..=191 => {
            bytes[0] = n as u8;
            &bytes[..1]
        }
        192..=8383 => {
            let n = n - 192;
            bytes[0] = 192 + (n >> 8) as u8;
            bytes[1] = n as u8;
            &bytes[..2]
        }
        _ => {
            bytes[0] = 255;
            bytes[1..].copy_from_slice(&n.to_be_bytes());
            bytes
        }
    }
}

enum Mode {
    Fixed { remaining: u32 },
    Partial { size: usize, pending: Vec<u8> },
}

/// A single packet body. Dropping it before finish leaves the parent unavailable
/// for further packets, since a partial packet may already be on the wire.
#[must_use = "write the packet body and call finish"]
pub struct PgpBodyWriter<'a, W> {
    parent: &'a mut PgpWriter<W>,
    mode: Mode,
    failed: bool,
}

impl<W: Write> PgpBodyWriter<'_, W> {
    /// Checks the fixed length or emits the final definite-length chunk.
    pub fn finish(self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("packet write failed"));
        }
        match self.mode {
            Mode::Fixed { remaining: 0 } => {}
            Mode::Fixed { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "incomplete fixed-length body",
                ));
            }
            Mode::Partial { pending, .. } => {
                write_length(&mut self.parent.inner, pending.len() as u32)?;
                self.parent.inner.write_all(&pending)?;
            }
        }
        self.parent.ready = true;
        Ok(())
    }
}

impl<W: Write> Write for PgpBodyWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other("packet write failed"));
        }
        match &mut self.mode {
            Mode::Fixed { remaining } => {
                if buf.len() > *remaining as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "body exceeds declared length",
                    ));
                }
                let n = self.parent.inner.write(buf)?;
                *remaining -= n as u32;
                Ok(n)
            }
            Mode::Partial { size, pending } => {
                let n = buf.len().min(*size - pending.len());
                pending.extend_from_slice(&buf[..n]);
                if pending.len() == *size {
                    self.failed = true;
                    self.parent
                        .inner
                        .write_all(&[224 + size.trailing_zeros() as u8])?;
                    self.parent.inner.write_all(pending)?;
                    pending.clear();
                    self.failed = false;
                }
                Ok(n)
            }
        }
    }

    /// Flushes the underlying stream. The pending partial chunk is framed by finish.
    fn flush(&mut self) -> io::Result<()> {
        self.parent.inner.flush()
    }
}
