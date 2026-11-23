use std::io::{self, Read, Write};

use tc_openpgp_packet::{ArmorKind, AsciiArmor};

use crate::PgpPublicKey;

mod default_serializer;

pub(crate) use default_serializer::DefaultPgpPublicKeySerializer;

#[cfg(feature = "cfrg-curves")]
pub(super) fn v6_fingerprint(algo: &dyn tc_algo::Algo, key: &PgpPublicKey) -> io::Result<[u8; 32]> {
    let packet = default_serializer::public_key_packet(key)?;
    if packet.version() != tc_openpgp_packet::PublicKeyVersion::V6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a v6 public key",
        ));
    }
    let mut input = Vec::new();
    packet.write_fingerprint_input(&mut input)?;
    algo.digest()
        .calculate_by_name("SHA-256", &input)
        .map_err(io::Error::other)?
        .try_into()
        .map_err(|_| io::Error::other("invalid SHA-256 digest length"))
}

/// Encodes and decodes one binary OpenPGP Public Key packet (tag 6).
pub trait PgpPublicKeySerializer: Send + Sync {
    /// Writes one complete public key packet to the output.
    fn encode_to(&self, key: &PgpPublicKey, out: &mut dyn Write) -> io::Result<()>;

    /// Reads one public key packet, leaving subsequent packets in the input.
    fn decode_from(&self, input: &mut dyn Read) -> io::Result<PgpPublicKey>;

    /// Armors the binary encoding of one Public Key packet.
    fn encode_armored(&self, key: &PgpPublicKey) -> io::Result<String> {
        AsciiArmor::encode(ArmorKind::PublicKey, &self.encode(key)?)
    }

    /// Decodes an armor block containing exactly one Public Key packet.
    fn decode_armored(&self, text: &str) -> io::Result<PgpPublicKey> {
        let bytes = AsciiArmor::decode(ArmorKind::PublicKey, text)?;
        let mut input = bytes.as_slice();
        let key = self.decode_from(&mut input)?;
        if !input.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing packets in public key armor",
            ));
        }
        Ok(key)
    }

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
