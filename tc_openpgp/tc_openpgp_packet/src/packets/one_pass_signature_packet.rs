use std::io::{self, Read, Write};

use crate::{
    BodyLength, DecodingConfig, EncodingConfig, HashAlgorithmTag, PacketTag, PgpRead, PgpReader,
    PgpWrite, PgpWriter, PublicKeyAlgorithmTag, SignatureTypeId,
};

/// A v6 One-Pass Signature packet, as defined in RFC 9580 Section 5.4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnePassSignaturePacket {
    signature_type: SignatureTypeId,
    hash_algorithm: HashAlgorithmTag,
    public_key_algorithm: PublicKeyAlgorithmTag,
    salt: Vec<u8>,
    fingerprint: [u8; 32],
    nesting_flag: u8,
}

impl OnePassSignaturePacket {
    pub fn new_v6(
        signature_type: SignatureTypeId,
        hash_algorithm: HashAlgorithmTag,
        public_key_algorithm: PublicKeyAlgorithmTag,
        salt: Vec<u8>,
        fingerprint: [u8; 32],
        another_follows: bool,
    ) -> Self {
        Self {
            signature_type,
            hash_algorithm,
            public_key_algorithm,
            salt,
            fingerprint,
            nesting_flag: u8::from(!another_follows),
        }
    }

    pub fn signature_type(&self) -> SignatureTypeId {
        self.signature_type
    }
    pub fn hash_algorithm(&self) -> HashAlgorithmTag {
        self.hash_algorithm
    }
    pub fn public_key_algorithm(&self) -> PublicKeyAlgorithmTag {
        self.public_key_algorithm
    }
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
    pub fn another_follows(&self) -> bool {
        self.nesting_flag == 0
    }
}

impl PgpRead for OnePassSignaturePacket {
    fn decode(input: &mut dyn Read, config: &DecodingConfig) -> io::Result<Self> {
        let mut reader = PgpReader::new(input);
        let (header, mut body) = reader.read_body(config)?;
        let BodyLength::Fixed(length) = header.body_length() else {
            return Err(invalid(
                "expected a definite-length One-Pass Signature packet",
            ));
        };
        if header.tag() != PacketTag::OnePassSignature {
            return Err(invalid("expected an OpenPGP One-Pass Signature packet"));
        }
        let mut version = [0];
        body.read_exact(&mut version)?;
        if version != [6] {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported one-pass signature version",
            ));
        }
        let mut fields = [0; 4];
        body.read_exact(&mut fields)?;
        let [signature_type, hash, public_key, salt_len] = fields;
        if length != 38 + u32::from(salt_len) {
            return Err(invalid("invalid One-Pass Signature packet length"));
        }
        let mut salt = vec![0; usize::from(salt_len)];
        body.read_exact(&mut salt)?;
        let mut fingerprint = [0; 32];
        body.read_exact(&mut fingerprint)?;
        let mut nesting_flag = [0];
        body.read_exact(&mut nesting_flag)?;
        Ok(Self {
            signature_type: signature_type.into(),
            hash_algorithm: hash.into(),
            public_key_algorithm: public_key.into(),
            salt,
            fingerprint,
            nesting_flag: nesting_flag[0],
        })
    }
}

impl PgpWrite for OnePassSignaturePacket {
    fn encode(&self, writer: &mut dyn Write, config: &EncodingConfig) -> io::Result<u64> {
        let salt_len = u8::try_from(self.salt.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "one-pass signature salt is too long",
            )
        })?;
        let length = 38 + u32::from(salt_len);
        let mut writer = PgpWriter::new(writer);
        let (mut body, header_len) = writer.write_body_with_format(
            PacketTag::OnePassSignature,
            BodyLength::Fixed(length),
            config.header_format,
        )?;
        body.write_all(&[
            6,
            self.signature_type.id(),
            self.hash_algorithm.into(),
            self.public_key_algorithm.into(),
            salt_len,
        ])?;
        body.write_all(&self.salt)?;
        body.write_all(&self.fingerprint)?;
        body.write_all(&[self.nesting_flag])?;
        body.finish()?;
        Ok(header_len + u64::from(length))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
