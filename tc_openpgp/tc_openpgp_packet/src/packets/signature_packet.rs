use std::io::{self, Read, Write};

use crate::{
    BodyLength, DecodingConfig, EncodingConfig, HashAlgorithmTag, PacketTag, PgpRead, PgpReader,
    PgpWrite, PgpWriter, PublicKeyAlgorithmTag, SignatureTypeId,
};

/// An OpenPGP v6 signature packet with algorithm-specific signature bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignaturePacket {
    signature_type: SignatureTypeId,
    public_key_algorithm: PublicKeyAlgorithmTag,
    hash_algorithm: HashAlgorithmTag,
    hashed_subpackets: Vec<u8>,
    unhashed_subpackets: Vec<u8>,
    hash_prefix: [u8; 2],
    salt: Vec<u8>,
    signature: Vec<u8>,
}

impl SignaturePacket {
    pub fn new_v6(
        signature_type: SignatureTypeId,
        public_key_algorithm: PublicKeyAlgorithmTag,
        hash_algorithm: HashAlgorithmTag,
        salt: Vec<u8>,
    ) -> Self {
        Self {
            signature_type,
            public_key_algorithm,
            hash_algorithm,
            salt,
            hashed_subpackets: Vec::new(),
            unhashed_subpackets: Vec::new(),
            hash_prefix: [0; 2],
            signature: Vec::new(),
        }
    }

    pub fn with_subpackets(mut self, hashed: Vec<u8>, unhashed: Vec<u8>) -> Self {
        self.hashed_subpackets = hashed;
        self.unhashed_subpackets = unhashed;
        self
    }

    pub fn with_signature(mut self, hash_prefix: [u8; 2], signature: Vec<u8>) -> Self {
        self.hash_prefix = hash_prefix;
        self.signature = signature;
        self
    }

    pub fn signature_type(&self) -> SignatureTypeId {
        self.signature_type
    }
    pub fn public_key_algorithm(&self) -> PublicKeyAlgorithmTag {
        self.public_key_algorithm
    }
    pub fn hash_algorithm(&self) -> HashAlgorithmTag {
        self.hash_algorithm
    }
    pub fn hashed_subpackets(&self) -> &[u8] {
        &self.hashed_subpackets
    }
    pub fn unhashed_subpackets(&self) -> &[u8] {
        &self.unhashed_subpackets
    }
    pub fn hash_prefix(&self) -> [u8; 2] {
        self.hash_prefix
    }
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Writes the hashed packet fields and v6 trailer, following the message data.
    pub fn write_hash_suffix(&self, output: &mut dyn Write) -> io::Result<()> {
        let header = self.hashed_header()?;
        output.write_all(&header)?;
        output.write_all(&self.hashed_subpackets)?;
        output.write_all(&[6, 0xff])?;
        let len = (header.len() as u32).wrapping_add(self.hashed_subpackets.len() as u32);
        output.write_all(&len.to_be_bytes())
    }

    fn hashed_header(&self) -> io::Result<[u8; 8]> {
        let [a, b, c, d] = checked_length(&self.hashed_subpackets)?.to_be_bytes();
        Ok([
            6,
            self.signature_type.id(),
            self.public_key_algorithm.into(),
            self.hash_algorithm.into(),
            a,
            b,
            c,
            d,
        ])
    }
}

impl PgpRead for SignaturePacket {
    fn decode(input: &mut dyn Read, config: &DecodingConfig) -> io::Result<Self> {
        let mut reader = PgpReader::new(input);
        let (header, mut body) = reader.read_body(config)?;
        if header.tag() != PacketTag::Signature
            || !matches!(header.body_length(), BodyLength::Fixed(_))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected a definite-length OpenPGP Signature packet",
            ));
        }
        let [version, typ, algorithm, hash] = read_bytes(&mut body)?;
        if version != 6 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only v6 OpenPGP signatures are supported",
            ));
        }
        let hashed = read_subpackets(&mut body)?;
        let unhashed = read_subpackets(&mut body)?;
        let hash_prefix = read_bytes(&mut body)?;
        let [salt_len] = read_bytes(&mut body)?;
        let mut salt = vec![0; usize::from(salt_len)];
        body.read_exact(&mut salt)?;
        let mut signature = Vec::new();
        body.read_to_end(&mut signature)?;
        Ok(
            Self::new_v6(typ.into(), algorithm.into(), hash.into(), salt)
                .with_subpackets(hashed, unhashed)
                .with_signature(hash_prefix, signature),
        )
    }
}

impl PgpWrite for SignaturePacket {
    fn encode(&self, output: &mut dyn Write, config: &EncodingConfig) -> io::Result<u64> {
        let header = self.hashed_header()?;
        let unhashed_len = checked_length(&self.unhashed_subpackets)?;
        let salt_len = u8::try_from(self.salt.len()).map_err(|_| too_long())?;
        let body_len = 15_u64
            + self.hashed_subpackets.len() as u64
            + u64::from(unhashed_len)
            + u64::from(salt_len)
            + u64::from(checked_length(&self.signature)?);
        let body_len = u32::try_from(body_len).map_err(|_| too_long())?;

        let mut writer = PgpWriter::new(output);
        let (mut body, header_len) = writer.write_body_with_format(
            PacketTag::Signature,
            BodyLength::Fixed(body_len),
            config.header_format,
        )?;
        body.write_all(&header)?;
        body.write_all(&self.hashed_subpackets)?;
        body.write_all(&unhashed_len.to_be_bytes())?;
        body.write_all(&self.unhashed_subpackets)?;
        body.write_all(&self.hash_prefix)?;
        body.write_all(&[salt_len])?;
        body.write_all(&self.salt)?;
        body.write_all(&self.signature)?;
        body.finish()?;
        Ok(header_len + u64::from(body_len))
    }
}

fn read_subpackets(input: &mut impl Read) -> io::Result<Vec<u8>> {
    let len = u32::from_be_bytes(read_bytes(input)?);
    let mut bytes = Vec::new();
    let count = input.take(u64::from(len)).read_to_end(&mut bytes)?;
    if count as u64 != u64::from(len) {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated OpenPGP signature subpackets",
        ));
    }
    Ok(bytes)
}

fn read_bytes<const N: usize>(input: &mut impl Read) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn checked_length(bytes: &[u8]) -> io::Result<u32> {
    u32::try_from(bytes.len()).map_err(|_| too_long())
}

fn too_long() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "OpenPGP signature field exceeds its length limit",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v6_signature_preserves_subpackets_salt_and_the_following_packet_boundary() {
        let packet = SignaturePacket::new_v6(
            SignatureTypeId::BINARY_DOCUMENT,
            PublicKeyAlgorithmTag::Ed25519,
            HashAlgorithmTag::Sha512,
            vec![1; 32],
        )
        .with_subpackets(vec![5, 2, 0, 0, 0, 1], vec![2, 99, 1])
        .with_signature([1, 2], vec![3; 64]);
        let mut bytes = Vec::new();
        let len = packet
            .encode(&mut bytes, &EncodingConfig::default())
            .unwrap();
        assert_eq!(len, bytes.len() as u64);
        bytes.extend_from_slice(b"next");
        let mut input = bytes.as_slice();
        assert_eq!(
            SignaturePacket::decode(&mut input, &DecodingConfig::default()).unwrap(),
            packet
        );
        assert_eq!(input, b"next");
        let max_body_len = len - 3;
        let mut input = bytes.as_slice();
        assert!(
            SignaturePacket::decode(
                &mut input,
                &DecodingConfig {
                    max_body_len,
                    ..DecodingConfig::default()
                }
            )
            .is_err()
        );

        let mut suffix = Vec::new();
        packet.write_hash_suffix(&mut suffix).unwrap();
        assert_eq!(
            suffix,
            [
                6, 0, 27, 10, 0, 0, 0, 6, 5, 2, 0, 0, 0, 1, 6, 0xff, 0, 0, 0, 14
            ],
        );
    }
}
