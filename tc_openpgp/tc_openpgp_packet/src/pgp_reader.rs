use std::io::{self, Read};

use crate::{BodyLength, DecodingConfig, PacketHeader, PacketHeaderFormat, PacketTag};

/// Reads OpenPGP packets from an underlying byte stream.
pub struct PgpReader<R> {
    inner: R,
}

impl<R: Read> PgpReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    pub(crate) fn read_body(
        &mut self,
        config: &DecodingConfig,
    ) -> io::Result<(PacketHeader, impl Read + '_)> {
        let [tag_octet] = read_bytes(&mut self.inner)?;
        if tag_octet & 0x80 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid packet tag octet",
            ));
        }

        let header_format = if tag_octet & 0x40 != 0 {
            PacketHeaderFormat::OpenPgp
        } else {
            PacketHeaderFormat::Legacy
        };
        if let Some(required) = config.header_format {
            if header_format != required {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected packet header format",
                ));
            }
        }

        let (tag, length) = if header_format == PacketHeaderFormat::OpenPgp {
            let tag = tag_octet & 0x3f;
            let length = read_openpgp_length(&mut self.inner)?;
            if let BodyLength::Partial(size) = length {
                if size < 512 || !matches!(tag, 8 | 9 | 11 | 18) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid first partial body length",
                    ));
                }
            }
            (tag, length)
        } else {
            let length = match tag_octet & 0x03 {
                0 => {
                    let [size] = read_bytes(&mut self.inner)?;
                    BodyLength::Fixed(u32::from(size))
                }
                1 => BodyLength::Fixed(u32::from(u16::from_be_bytes(read_bytes(&mut self.inner)?))),
                2 => BodyLength::Fixed(u32::from_be_bytes(read_bytes(&mut self.inner)?)),
                _ => BodyLength::Indeterminate,
            };
            ((tag_octet >> 2) & 0x0f, length)
        };

        let mut remaining_budget = config.max_body_len;
        reserve_segment(length, &mut remaining_budget)?;
        Ok((
            PacketHeader::new(
                PacketTag::from(tag),
                header_format == PacketHeaderFormat::OpenPgp,
                length,
            ),
            BodyReader {
                inner: &mut self.inner,
                length,
                remaining_budget,
            },
        ))
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

struct BodyReader<'a, R> {
    inner: &'a mut R,
    length: BodyLength,
    remaining_budget: u64,
}

impl<R: Read> Read for BodyReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.length == BodyLength::Partial(0) {
            let length = read_openpgp_length(self.inner)?;
            reserve_segment(length, &mut self.remaining_budget)?;
            self.length = length;
        }

        let remaining = match &mut self.length {
            BodyLength::Fixed(0) => return Ok(0),
            BodyLength::Fixed(remaining) | BodyLength::Partial(remaining) => remaining,
            BodyLength::Indeterminate => return self.read_indeterminate(buf),
        };
        let limit = buf
            .len()
            .min(usize::try_from(*remaining).unwrap_or(usize::MAX));
        let count = self.inner.read(&mut buf[..limit])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated packet body",
            ));
        }
        *remaining -= count as u32;
        Ok(count)
    }
}

impl<R: Read> BodyReader<'_, R> {
    fn read_indeterminate(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let limit = buf
            .len()
            .min(usize::try_from(self.remaining_budget).unwrap_or(usize::MAX));
        if limit == 0 {
            return match self.inner.read(&mut [0; 1])? {
                0 => Ok(0),
                _ => Err(body_limit_error()),
            };
        }

        let count = self.inner.read(&mut buf[..limit])?;
        self.remaining_budget -= count as u64;
        Ok(count)
    }
}

fn reserve_segment(length: BodyLength, budget: &mut u64) -> io::Result<()> {
    if let BodyLength::Fixed(size) | BodyLength::Partial(size) = length {
        *budget = budget
            .checked_sub(u64::from(size))
            .ok_or_else(body_limit_error)?;
    }
    Ok(())
}

fn body_limit_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "packet body exceeds configured length limit",
    )
}

fn read_openpgp_length(input: &mut impl Read) -> io::Result<BodyLength> {
    let [first] = read_bytes(input)?;
    Ok(match first {
        0..=191 => BodyLength::Fixed(u32::from(first)),
        192..=223 => {
            let [second] = read_bytes(input)?;
            BodyLength::Fixed(((u32::from(first) - 192) << 8) + u32::from(second) + 192)
        }
        224..=254 => BodyLength::Partial(1 << (first & 0x1f)),
        255 => BodyLength::Fixed(u32::from_be_bytes(read_bytes(input)?)),
    })
}

fn read_bytes<const N: usize>(input: &mut impl Read) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}
