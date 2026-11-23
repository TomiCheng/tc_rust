use std::io::{self, Write};

use tc_encoders::{Encoder, base64::DEFAULT};

/// The label of an OpenPGP ASCII Armor block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmorKind {
    Message,
    PublicKey,
    PrivateKey,
    Signature,
}

impl ArmorKind {
    fn label(self) -> &'static str {
        match self {
            Self::Message => "PGP MESSAGE",
            Self::PublicKey => "PGP PUBLIC KEY BLOCK",
            Self::PrivateKey => "PGP PRIVATE KEY BLOCK",
            Self::Signature => "PGP SIGNATURE",
        }
    }
}

pub struct AsciiArmor;

impl AsciiArmor {
    /// Encodes one block without the deprecated CRC24 footer.
    pub fn encode(kind: ArmorKind, bytes: &[u8]) -> io::Result<String> {
        let mut output = Vec::new();
        Self::encode_to(kind, bytes, &mut output)?;
        String::from_utf8(output).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub fn encode_to(kind: ArmorKind, bytes: &[u8], output: &mut dyn Write) -> io::Result<()> {
        writeln!(output, "-----BEGIN {}-----\n", kind.label())?;
        let mut line = [0; 64];
        for chunk in bytes.chunks(48) {
            let len = DEFAULT.encode(chunk, &mut line).map_err(base64_error)?;
            output.write_all(&line[..len])?;
            output.write_all(b"\n")?;
        }
        writeln!(output, "-----END {}-----", kind.label())
    }

    /// Decodes one block. Legacy CRC24 footer contents are ignored.
    pub fn decode(kind: ArmorKind, text: &str) -> io::Result<Vec<u8>> {
        let mut lines = text.lines().map(str::trim_ascii);
        let begin = format!("-----BEGIN {}-----", kind.label());
        let end = format!("-----END {}-----", kind.label());
        if lines.find(|line| !line.is_empty()) != Some(begin.as_str()) {
            return Err(invalid_armor("unexpected OpenPGP armor header"));
        }
        loop {
            match lines.next() {
                Some("") => break,
                Some(header)
                    if header
                        .split_once(':')
                        .is_some_and(|(key, _)| !key.is_empty()) => {}
                _ => return Err(invalid_armor("missing OpenPGP armor header separator")),
            }
        }

        let mut encoded = Vec::new();
        let mut checksum_seen = false;
        for line in lines.by_ref() {
            if line == end {
                if lines.any(|line| !line.is_empty()) {
                    return Err(invalid_armor("trailing data after OpenPGP armor"));
                }
                return DEFAULT.decode_to_vec(&encoded).map_err(base64_error);
            }
            if line.is_empty() {
                continue;
            }
            if checksum_seen {
                return Err(invalid_armor(
                    "unexpected data after OpenPGP armor checksum",
                ));
            }
            if line.starts_with('=') {
                checksum_seen = true;
            } else {
                encoded.extend_from_slice(line.as_bytes());
            }
        }
        Err(invalid_armor("missing OpenPGP armor footer"))
    }
}

fn invalid_armor(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn base64_error(error: tc_encoders::EncoderError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn armor_round_trips_each_block_kind_and_wraps_base64_lines() {
        let bytes = [0x95; 120];
        for kind in [
            ArmorKind::Message,
            ArmorKind::PublicKey,
            ArmorKind::PrivateKey,
            ArmorKind::Signature,
        ] {
            let armor = AsciiArmor::encode(kind, &bytes).unwrap();
            assert_eq!(AsciiArmor::decode(kind, &armor).unwrap(), bytes);
            assert!(
                armor
                    .lines()
                    .skip(2)
                    .take(3)
                    .all(|line| line.len() <= 64 && !line.starts_with('='))
            );
        }
    }

    #[test]
    fn armor_accepts_legacy_headers_and_ignores_a_bad_crc_but_checks_its_labels() {
        let text = "-----BEGIN PGP SIGNATURE-----\r\nVersion: BCPG\r\n\r\nYWJj\r\n=bad\r\n-----END PGP SIGNATURE-----\r\n";
        assert_eq!(
            AsciiArmor::decode(ArmorKind::Signature, text).unwrap(),
            b"abc"
        );
        assert!(AsciiArmor::decode(ArmorKind::Message, text).is_err());
        assert!(AsciiArmor::decode(ArmorKind::Signature, &text.replace("YWJj", "YW!j")).is_err());
        assert!(
            AsciiArmor::decode(
                ArmorKind::Signature,
                &text.replace("END PGP SIGNATURE", "END PGP MESSAGE")
            )
            .is_err()
        );
    }
}
