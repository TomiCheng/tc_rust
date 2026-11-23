use std::io::{self, Read};

use tc_openpgp_packet::{BodyLength, DecodingConfig, LiteralData, PacketTag, PgpRead, PgpReader};
use tc_zeroize::Zeroizing;
use tc_zlib::{InflateOptions, ZlibReader};

const MAX_EXPANDED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMPRESSION_DEPTH: u8 = 4;

pub(super) fn decode(
    input: &[u8],
    config: &DecodingConfig,
    allow_padding: bool,
) -> io::Result<LiteralData> {
    let config = DecodingConfig {
        header_format: None,
        ..*config
    };
    let mut budget = config.max_body_len.min(MAX_EXPANDED_BYTES);
    decode_packets(input, &config, allow_padding, 0, &mut budget)
}

fn decode_packets(
    mut input: &[u8],
    config: &DecodingConfig,
    allow_padding: bool,
    depth: u8,
    budget: &mut u64,
) -> io::Result<LiteralData> {
    let tag = {
        let mut reader = PgpReader::new(input);
        let (header, _) = reader.read_body(config)?;
        header.tag()
    };
    let literal = match tag {
        PacketTag::LiteralData => LiteralData::decode(&mut input, config)?,
        PacketTag::CompressedData => {
            if depth >= MAX_COMPRESSION_DEPTH {
                return Err(invalid("OpenPGP compression nesting limit exceeded"));
            }
            let expanded = {
                let mut reader = PgpReader::new(&mut input);
                let (_, mut body) = reader.read_body(config)?;
                let mut algorithm = [0];
                body.read_exact(&mut algorithm)?;
                let zlib = match algorithm[0] {
                    1 => false,
                    2 => true,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "unsupported OpenPGP compression algorithm",
                        ));
                    }
                };
                let mut compressed = Zeroizing::new(Vec::new());
                body.read_to_end(&mut compressed)?;
                inflate(&compressed, zlib, budget)?
            };
            decode_packets(&expanded, config, allow_padding, depth + 1, budget)?
        }
        _ => return Err(invalid("expected OpenPGP literal or compressed data")),
    };
    while !input.is_empty() && allow_padding {
        let mut reader = PgpReader::new(&mut input);
        let (header, mut body) = reader.read_body(config)?;
        if header.tag() != PacketTag::Padding
            || !matches!(header.body_length(), BodyLength::Fixed(_))
        {
            return Err(invalid("unexpected trailing packets in OpenPGP message"));
        }
        io::copy(&mut body, &mut io::sink())?;
    }
    if !input.is_empty() {
        return Err(invalid("unexpected trailing packets in OpenPGP message"));
    }
    Ok(literal)
}

fn inflate(input: &[u8], zlib: bool, budget: &mut u64) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut decoder = ZlibReader::decompress(input, InflateOptions::default().nowrap(!zlib));
    let mut output = Zeroizing::new(Vec::new());
    (&mut decoder).take(*budget + 1).read_to_end(&mut output)?;
    *budget = budget
        .checked_sub(output.len() as u64)
        .ok_or_else(|| invalid("OpenPGP decompressed size exceeds limit"))?;
    if !decoder.buffered_input().is_empty() || !decoder.get_ref().is_empty() {
        return Err(invalid("trailing bytes after OpenPGP compressed stream"));
    }
    Ok(output)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tc_openpgp_packet::{EncodingConfig, PgpWrite, PgpWriter};
    use tc_zlib::{DeflateOptions, ZlibWriter};

    fn compressed(data: &[u8], zlib: bool) -> Vec<u8> {
        let mut compressor =
            ZlibWriter::compress(Vec::new(), DeflateOptions::default().nowrap(!zlib));
        compressor.write_all(data).unwrap();
        let encoded = compressor.finish().unwrap();
        let mut bytes = Vec::new();
        let mut writer = PgpWriter::new(&mut bytes);
        let mut body = writer
            .write_body(
                PacketTag::CompressedData,
                BodyLength::Fixed(encoded.len() as u32 + 1),
            )
            .unwrap();
        body.write_all(&[if zlib { 2 } else { 1 }]).unwrap();
        body.write_all(&encoded).unwrap();
        body.finish().unwrap();
        bytes
    }

    #[test]
    fn handles_both_algorithms_and_caps_output_and_nesting() {
        let mut literal = Vec::new();
        LiteralData::with_data(&[42; 8192])
            .encode(&mut literal, &EncodingConfig::default())
            .unwrap();
        let config = DecodingConfig::default();
        for zlib in [false, true] {
            let packet = compressed(&literal, zlib);
            assert_eq!(decode(&packet, &config, false).unwrap().data(), &[42; 8192]);
            let smaller = DecodingConfig {
                max_body_len: 4096,
                ..config
            };
            assert!(
                decode(&packet, &smaller, false)
                    .unwrap_err()
                    .to_string()
                    .contains("size exceeds")
            );
        }
        let mut packet = literal;
        for _ in 0..MAX_COMPRESSION_DEPTH {
            packet = compressed(&packet, true);
        }
        assert!(decode(&packet, &config, false).is_ok());
        assert!(
            decode(&compressed(&packet, false), &config, false)
                .unwrap_err()
                .to_string()
                .contains("nesting limit")
        );
    }

    #[test]
    fn rejects_truncated_stream_and_extra_data() {
        let packet = compressed(b"inner payload", true);
        let mut stream = &packet[3..packet.len() - 1];
        assert!(inflate(stream, true, &mut 1024).is_err());
        let mut extended = packet[3..].to_vec();
        extended.push(0);
        stream = &extended;
        assert!(inflate(stream, true, &mut 1024).is_err());

        let mut literal = Vec::new();
        LiteralData::with_data(b"ok")
            .encode(&mut literal, &EncodingConfig::default())
            .unwrap();
        literal.extend_from_slice(&[0xc2, 0]);
        assert!(decode(&literal, &DecodingConfig::default(), true).is_err());
    }
}
