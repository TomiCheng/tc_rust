use std::io::{self, Read, Write};

use crate::{
    BodyLength, DecodingConfig, EncodingConfig, PacketTag, PgpRead, PgpReader, PgpWrite, PgpWriter,
    PublicKeyAlgorithmTag,
};

/// Version of the Public Key packet body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PublicKeyVersion {
    V4 = 4,
    V6 = 6,
}

impl TryFrom<u8> for PublicKeyVersion {
    type Error = io::Error;

    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            4 => Ok(Self::V4),
            6 => Ok(Self::V6),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported OpenPGP public key version",
            )),
        }
    }
}

/// A Tag 6 Public Key packet with opaque algorithm-specific public key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyPacket {
    version: PublicKeyVersion,
    creation_time: u32,
    algorithm: PublicKeyAlgorithmTag,
    key_material: Vec<u8>,
}

impl PublicKeyPacket {
    pub fn new(
        version: PublicKeyVersion,
        creation_time: u32,
        algorithm: PublicKeyAlgorithmTag,
        key_material: Vec<u8>,
    ) -> Self {
        Self {
            version,
            creation_time,
            algorithm,
            key_material,
        }
    }

    pub fn version(&self) -> PublicKeyVersion {
        self.version
    }

    /// Seconds since the Unix epoch.
    pub fn creation_time(&self) -> u32 {
        self.creation_time
    }

    pub fn algorithm(&self) -> PublicKeyAlgorithmTag {
        self.algorithm
    }

    pub fn key_material(&self) -> &[u8] {
        &self.key_material
    }
}

impl PgpRead for PublicKeyPacket {
    fn decode(input: &mut dyn Read, config: &DecodingConfig) -> io::Result<Self> {
        let mut reader = PgpReader::new(input);
        let (header, mut body) = reader.read_body(config)?;
        if header.tag() != PacketTag::PublicKey {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected an OpenPGP Public Key packet",
            ));
        }
        let BodyLength::Fixed(body_len) = header.body_length() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "public key requires a definite body length",
            ));
        };

        let mut prefix = [0; 6];
        body.read_exact(&mut prefix)?;
        let [version, a, b, c, d, algorithm] = prefix;
        let version = PublicKeyVersion::try_from(version)?;
        if version == PublicKeyVersion::V6 {
            let mut size = [0; 4];
            body.read_exact(&mut size)?;
            if Some(u32::from_be_bytes(size)) != body_len.checked_sub(10) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incorrect public key material length",
                ));
            }
        }
        let mut key_material = Vec::new();
        body.read_to_end(&mut key_material)?;
        Ok(Self::new(
            version,
            u32::from_be_bytes([a, b, c, d]),
            algorithm.into(),
            key_material,
        ))
    }
}

impl PgpWrite for PublicKeyPacket {
    fn encode(&self, writer: &mut dyn Write, config: &EncodingConfig) -> io::Result<u64> {
        let prefix_len = match self.version {
            PublicKeyVersion::V4 => 6,
            PublicKeyVersion::V6 => 10,
        };
        let material_len = u32::try_from(self.key_material.len())
            .ok()
            .filter(|len| len.checked_add(prefix_len).is_some())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "public key packet body is too long",
                )
            })?;
        let body_len = material_len + prefix_len;

        let mut writer = PgpWriter::new(writer);
        let (mut body, header_len) = writer.write_body_with_format(
            PacketTag::PublicKey,
            BodyLength::Fixed(body_len),
            config.header_format,
        )?;
        body.write_all(&[self.version as u8])?;
        body.write_all(&self.creation_time.to_be_bytes())?;
        body.write_all(&[self.algorithm.into()])?;
        if self.version == PublicKeyVersion::V6 {
            body.write_all(&material_len.to_be_bytes())?;
        }
        body.write_all(&self.key_material)?;
        body.finish()?;
        Ok(header_len + u64::from(body_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PacketHeaderFormat;

    #[test]
    fn public_key_packets_round_trip_with_current_and_legacy_framing() {
        for version in [PublicKeyVersion::V4, PublicKeyVersion::V6] {
            for header_format in [PacketHeaderFormat::OpenPgp, PacketHeaderFormat::Legacy] {
                let packet = PublicKeyPacket::new(
                    version,
                    0x0102_0304,
                    PublicKeyAlgorithmTag::Unknown(99),
                    vec![0xde, 0xad],
                );
                let mut encoded = Vec::new();
                let written = packet
                    .encode(&mut encoded, &EncodingConfig { header_format })
                    .unwrap();
                assert_eq!(encoded.len() as u64, written);
                assert_eq!(
                    encoded[0],
                    match header_format {
                        PacketHeaderFormat::OpenPgp => 0xc6,
                        PacketHeaderFormat::Legacy => 0x98,
                    }
                );
                assert_eq!(&encoded[2..8], &[version as u8, 1, 2, 3, 4, 99]);
                if version == PublicKeyVersion::V6 {
                    assert_eq!(&encoded[8..12], &[0, 0, 0, 2]);
                }
                encoded.extend_from_slice(b"next");
                let config = DecodingConfig {
                    max_body_len: written - 2,
                    header_format: Some(header_format),
                };
                let mut input = encoded.as_slice();
                assert_eq!(
                    PublicKeyPacket::decode(&mut input, &config).unwrap(),
                    packet
                );
                assert_eq!(input, b"next");
            }
        }
    }

    #[test]
    fn public_key_decoding_rejects_mismatched_lengths_and_nondefinite_headers() {
        let mut malformed = &b"\xc6\x0b\x06\x00\x00\x00\x00\x1b\x00\x00\x00\x02\x99"[..];
        assert_eq!(
            PublicKeyPacket::decode(&mut malformed, &DecodingConfig::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let mut legacy_indeterminate = &b"\x9b\x04\x00\x00\x00\x00\x01"[..];
        assert_eq!(
            PublicKeyPacket::decode(&mut legacy_indeterminate, &DecodingConfig::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let mut short_v6 = &b"\xc6\x06\x06\x00\x00\x00\x00\x1bnext"[..];
        assert_eq!(
            PublicKeyPacket::decode(&mut short_v6, &DecodingConfig::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(short_v6, b"next");
    }
}
