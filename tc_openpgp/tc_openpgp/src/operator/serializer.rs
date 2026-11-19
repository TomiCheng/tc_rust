use std::io::{self, Read, Write};

use crate::PgpPublicKey;

/// Encodes and decodes one binary OpenPGP Public Key packet (tag 6).
pub trait PgpPublicKeySerializer: Send + Sync {
    /// Writes one complete public key packet to the output.
    fn encode_to(&self, key: &PgpPublicKey, out: &mut dyn Write) -> io::Result<()>;

    /// Reads one public key packet, leaving subsequent packets in the input.
    fn decode_from(&self, input: &mut dyn Read) -> io::Result<PgpPublicKey>;

    fn encode(&self, key: &PgpPublicKey) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.encode_to(key, &mut bytes)?;
        Ok(bytes)
    }

    fn decode(&self, mut bytes: &[u8]) -> io::Result<PgpPublicKey> {
        self.decode_from(&mut bytes)
    }
}

pub(crate) struct EmptyPgpPublicKeySerializer;

impl PgpPublicKeySerializer for EmptyPgpPublicKeySerializer {
    fn encode_to(&self, _key: &PgpPublicKey, _out: &mut dyn Write) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn decode_from(&self, _input: &mut dyn Read) -> io::Result<PgpPublicKey> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
