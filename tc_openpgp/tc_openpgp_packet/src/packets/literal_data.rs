use std::io::{self, Read, Write};

use crate::{
    BodyLength, DecodingConfig, EncodingConfig, LiteralDataFormat, PacketHeaderFormat, PacketTag,
    PgpRead, PgpReader, PgpWrite, PgpWriter,
};

/// An OpenPGP Literal Data packet (Tag 11).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LiteralData {
    format: LiteralDataFormat,
    filename: Vec<u8>,
    timestamp: u32,
    data: Vec<u8>,
}

impl LiteralData {
    /// Creates a packet with a payload format and a filename of up to 255 bytes.
    pub fn new(
        format: LiteralDataFormat,
        filename: Vec<u8>,
        timestamp: u32,
        data: Vec<u8>,
    ) -> io::Result<Self> {
        validate_filename(&filename)?;

        Ok(Self {
            format,
            filename,
            timestamp,
            data,
        })
    }

    /// Creates a UTF-8 text packet with CRLF line endings and empty file metadata.
    pub fn with_str(text: &str) -> Self {
        let mut data = Vec::with_capacity(text.len());
        let mut bytes = text.bytes().peekable();
        while let Some(byte) = bytes.next() {
            match byte {
                b'\r' => {
                    bytes.next_if_eq(&b'\n');
                    data.extend_from_slice(b"\r\n");
                }
                b'\n' => data.extend_from_slice(b"\r\n"),
                _ => data.push(byte),
            }
        }

        Self {
            format: LiteralDataFormat::Utf8,
            filename: Vec::new(),
            timestamp: 0,
            data,
        }
    }

    /// Creates a binary packet by copying the payload bytes as-is.
    pub fn with_data(data: &[u8]) -> Self {
        Self {
            format: LiteralDataFormat::Binary,
            filename: Vec::new(),
            timestamp: 0,
            data: data.to_vec(),
        }
    }

    /// Returns the payload format.
    pub fn format(&self) -> LiteralDataFormat {
        self.format
    }

    pub fn filename(&self) -> &[u8] {
        &self.filename
    }

    /// Sets the file name. Returns an error if it exceeds 255 bytes.
    pub fn set_filename(&mut self, filename: impl AsRef<[u8]>) -> io::Result<()> {
        let filename = filename.as_ref();
        validate_filename(filename)?;
        self.filename = filename.to_vec();
        Ok(())
    }

    /// Returns the timestamp in Unix seconds, or zero if unspecified.
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Sets the timestamp in Unix seconds. Use zero to clear it.
    pub fn set_timestamp(&mut self, timestamp: u32) {
        self.timestamp = timestamp;
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl PgpRead for LiteralData {
    fn decode(input: &mut dyn Read, config: &DecodingConfig) -> io::Result<Self> {
        let mut reader = PgpReader::new(input);
        let (tag, mut body) = reader.read_body(config)?;
        if tag != PacketTag::LiteralData {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected a Literal Data packet",
            ));
        }

        let mut prefix = [0; 2];
        body.read_exact(&mut prefix)?;
        let [format, filename_len] = prefix;
        let mut filename = vec![0; usize::from(filename_len)];
        body.read_exact(&mut filename)?;
        let mut timestamp = [0; 4];
        body.read_exact(&mut timestamp)?;
        let mut data = Vec::new();
        body.read_to_end(&mut data)?;

        Ok(Self {
            format: LiteralDataFormat::from(format),
            filename,
            timestamp: u32::from_be_bytes(timestamp),
            data,
        })
    }
}

impl PgpWrite for LiteralData {
    /// Writes a complete Literal Data packet with a definite body length.
    /// Legacy framing is available only in builds with debug assertions.
    fn encode(&self, writer: &mut dyn Write, config: &EncodingConfig) -> io::Result<u64> {
        if !cfg!(debug_assertions) && config.header_format == PacketHeaderFormat::Legacy {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "legacy Literal Data encoding requires debug assertions",
            ));
        }

        let body_len = u32::try_from(self.data.len())
            .ok()
            .and_then(|len| len.checked_add(6 + self.filename.len() as u32))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "literal data body exceeds the definite-length limit",
                )
            })?;

        let mut packet_writer = PgpWriter::new(writer);
        let (mut body, header_len) = packet_writer.write_body_with_format(
            PacketTag::LiteralData,
            BodyLength::Fixed(body_len),
            config.header_format,
        )?;
        body.write_all(&[u8::from(self.format), self.filename.len() as u8])?;
        body.write_all(&self.filename)?;
        body.write_all(&self.timestamp.to_be_bytes())?;
        body.write_all(&self.data)?;
        body.finish()?;
        Ok(header_len + u64::from(body_len))
    }
}

fn validate_filename(filename: &[u8]) -> io::Result<()> {
    if filename.len() > usize::from(u8::MAX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "literal data filename exceeds 255 bytes",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_enforces_total_body_limit_for_each_framing() {
        let mut partial = b"\xcb\xe9b\x00\x00\x00\x00\x00".to_vec();
        partial.extend_from_slice(&[b'a'; 506]);
        partial.extend_from_slice(b"\x01b");
        for (bytes, body_len) in [
            (&b"\xcb\x07b\x00\x00\x00\x00\x00z"[..], 7),
            (&b"\xac\x07b\x00\x00\x00\x00\x00z"[..], 7),
            (&b"\xafb\x00\x00\x00\x00\x00z"[..], 7),
            (partial.as_slice(), 513),
        ] {
            let mut config = DecodingConfig {
                max_body_len: body_len,
                ..DecodingConfig::default()
            };
            let packet = LiteralData::decode(&mut &bytes[..], &config).unwrap();
            assert_eq!(packet.data().len() as u64 + 6, body_len);

            config.max_body_len -= 1;
            let error = LiteralData::decode(&mut &bytes[..], &config).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn decode_requires_the_configured_header_format() {
        let current = &b"\xcb\x06b\x00\x00\x00\x00\x00"[..];
        let legacy = &b"\xac\x06b\x00\x00\x00\x00\x00"[..];
        for (format, accepted, rejected) in [
            (PacketHeaderFormat::OpenPgp, current, legacy),
            (PacketHeaderFormat::Legacy, legacy, current),
        ] {
            let config = DecodingConfig {
                header_format: Some(format),
                ..DecodingConfig::default()
            };
            assert!(LiteralData::decode(&mut &accepted[..], &config).is_ok());
            let mut input = rejected;
            let error = LiteralData::decode(&mut input, &config).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(input, &rejected[1..]);
        }
    }

    #[test]
    fn decode_reads_consecutive_current_and_legacy_packets() {
        let mut input = &b"\xcb\x0ab\x01x\x01\x02\x03\x04abc\xac\x07u\x00\x00\x00\x00\x00z"[..];
        let binary = LiteralData::decode(&mut input, &DecodingConfig::default()).unwrap();
        assert_eq!(binary.format(), LiteralDataFormat::Binary);
        assert_eq!(binary.filename(), b"x");
        assert_eq!(binary.timestamp(), 0x0102_0304);
        assert_eq!(binary.data(), b"abc");
        assert_eq!(
            LiteralData::decode(&mut input, &DecodingConfig::default()).unwrap(),
            LiteralData::with_str("z")
        );
        assert!(input.is_empty());
    }

    #[test]
    fn decode_reads_partial_chunks_and_stops_at_the_final_chunk() {
        let mut bytes = b"\xcb\xe9b\x00\x00\x00\x00\x00".to_vec();
        bytes.extend_from_slice(&[b'a'; 506]);
        bytes.extend_from_slice(b"\xe0b\x00next");
        let mut input = bytes.as_slice();

        let packet = LiteralData::decode(&mut input, &DecodingConfig::default()).unwrap();
        assert_eq!(&packet.data()[..506], &[b'a'; 506]);
        assert_eq!(&packet.data()[506..], b"b");
        assert_eq!(input, b"next");
    }

    #[test]
    fn decode_rejects_truncated_packets_and_other_tags() {
        for mut input in [
            &b"\xcb\x07b\x00\x00\x00\x00\x00"[..],
            &b"\xcb\x06b\x01\x00\x00\x00\x00"[..],
            &b"\xcb\xe9b\x00\x00\x00\x00\x00"[..],
        ] {
            assert_eq!(
                LiteralData::decode(&mut input, &DecodingConfig::default())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        let mut input = &b"\xca\x03PGP"[..];
        assert_eq!(
            LiteralData::decode(&mut input, &DecodingConfig::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn decode_reads_indeterminate_legacy_body_to_eof() {
        let mut input = &b"\xafb\x00\x00\x00\x00\x00abc"[..];
        assert_eq!(
            LiteralData::decode(&mut input, &DecodingConfig::default()).unwrap(),
            LiteralData::with_data(b"abc")
        );
        assert!(input.is_empty());
    }

    #[test]
    fn encode_writes_the_header_and_literal_body() {
        let mut packet = LiteralData::with_data(b"abc");
        packet.set_filename("x").unwrap();
        packet.set_timestamp(0x0102_0304);
        let mut output = Vec::new();

        let written = packet
            .encode(&mut output, &EncodingConfig::default())
            .unwrap();

        assert_eq!(output, b"\xcb\x0ab\x01x\x01\x02\x03\x04abc");
        assert_eq!(written, output.len() as u64);
    }

    #[test]
    fn encode_reports_total_length_for_all_definite_length_header_sizes() {
        for (body_len, encoded_len) in [
            (191, &[191][..]),
            (192, &[192, 0][..]),
            (8383, &[223, 255][..]),
            (8384, &[255, 0, 0, 0x20, 0xc0][..]),
        ] {
            let packet = LiteralData::with_data(&vec![0; body_len - 6]);
            let mut output = Vec::new();

            let written = packet
                .encode(&mut output, &EncodingConfig::default())
                .unwrap();

            assert_eq!(output[0], 0xcb);
            assert_eq!(&output[1..1 + encoded_len.len()], encoded_len);
            assert_eq!(written, (1 + encoded_len.len() + body_len) as u64);
            assert_eq!(written, output.len() as u64);
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn encode_writes_legacy_headers_with_each_definite_length_width() {
        let config = EncodingConfig {
            header_format: PacketHeaderFormat::Legacy,
        };
        for (body_len, expected_header) in [
            (9, &[0xac, 9][..]),
            (255, &[0xac, 0xff][..]),
            (256, &[0xad, 1, 0][..]),
            (65535, &[0xad, 0xff, 0xff][..]),
            (65536, &[0xae, 0, 1, 0, 0][..]),
        ] {
            let packet = LiteralData::with_data(&vec![0x42; body_len - 6]);
            let mut output = Vec::new();

            let written = packet.encode(&mut output, &config).unwrap();

            assert_eq!(&output[..expected_header.len()], expected_header);
            let body = &output[expected_header.len()..];
            assert_eq!(&body[..6], &[b'b', 0, 0, 0, 0, 0]);
            assert_eq!(&body[6..], packet.data());
            assert_eq!(written, output.len() as u64);
        }
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn encode_rejects_legacy_framing_without_debug_assertions() {
        let packet = LiteralData::with_data(b"abc");
        let config = EncodingConfig {
            header_format: PacketHeaderFormat::Legacy,
        };
        let mut output = Vec::new();

        let error = packet.encode(&mut output, &config).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(output.is_empty());
    }

    #[test]
    fn setters_update_metadata_and_preserve_filename_on_error() {
        let mut packet = LiteralData::with_data(b"payload");
        let filename = "名".repeat(85);

        packet.set_filename(filename.as_str()).unwrap();
        packet.set_timestamp(1_700_000_000);
        let error = packet.set_filename([b'x'; 256]).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(packet.filename(), filename.as_bytes());
        assert_eq!(packet.timestamp(), 1_700_000_000);
    }

    #[test]
    fn with_str_normalizes_line_endings_and_uses_empty_file_metadata() {
        let packet = LiteralData::with_str("第一行\n第二行\r\n第三行\r");

        assert_eq!(packet.data(), "第一行\r\n第二行\r\n第三行\r\n".as_bytes());
        assert_eq!(packet.format(), LiteralDataFormat::Utf8);
        assert!(packet.filename().is_empty());
        assert_eq!(packet.timestamp(), 0);
    }
}
