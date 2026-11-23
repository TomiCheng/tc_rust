use std::io::{self, Read, Write};

use tc_algo::Params;
use tc_openpgp_packet::{
    DecodingConfig, EncodingConfig, PgpRead, PgpWrite, PublicKeyAlgorithmTag, PublicKeyPacket,
};

use super::PgpPublicKeySerializer;
use crate::PgpPublicKey;

#[cfg(feature = "rsa")]
mod rsa;

#[cfg(feature = "cfrg-curves")]
mod curve25519;

// Two MPIs, each at most 65535 bits plus its two-byte length, and a v6 body prefix.
const MAX_PUBLIC_KEY_BODY_LEN: u64 = 2 * (8192 + 2) + 10;

pub(crate) struct DefaultPgpPublicKeySerializer;

impl PgpPublicKeySerializer for DefaultPgpPublicKeySerializer {
    fn encode_to(&self, key: &PgpPublicKey, out: &mut dyn Write) -> io::Result<()> {
        public_key_packet(key)?.encode(out, &EncodingConfig::default())?;
        Ok(())
    }

    fn decode_from(&self, input: &mut dyn Read) -> io::Result<PgpPublicKey> {
        let packet = PublicKeyPacket::decode(
            input,
            &DecodingConfig {
                max_body_len: MAX_PUBLIC_KEY_BODY_LEN,
                ..DecodingConfig::default()
            },
        )?;
        decode_key_packet(&packet)
    }
}

pub(in crate::operator) fn decode_key_packet(packet: &PublicKeyPacket) -> io::Result<PgpPublicKey> {
    let key = decode_key_material(packet.algorithm(), packet.key_material())?;
    Ok(PgpPublicKey::new_with_metadata(
        packet.algorithm(),
        key,
        packet.version(),
        packet.creation_time(),
    ))
}

pub(in crate::operator) fn public_key_packet(key: &PgpPublicKey) -> io::Result<PublicKeyPacket> {
    Ok(PublicKeyPacket::new(
        key.version(),
        key.creation_time(),
        key.algorithm(),
        encode_key_material(key.algorithm(), key.key())?,
    ))
}

fn encode_key_material(tag: PublicKeyAlgorithmTag, _key: &dyn Params) -> io::Result<Vec<u8>> {
    match tag {
        #[cfg(feature = "rsa")]
        PublicKeyAlgorithmTag::RsaGeneral
        | PublicKeyAlgorithmTag::RsaEncrypt
        | PublicKeyAlgorithmTag::RsaSign => rsa::encode(_key),
        #[cfg(feature = "cfrg-curves")]
        PublicKeyAlgorithmTag::Ed25519 => curve25519::encode_ed25519(_key),
        #[cfg(feature = "cfrg-curves")]
        PublicKeyAlgorithmTag::X25519 => curve25519::encode_x25519(_key),
        _ => Err(unsupported_algorithm(tag)),
    }
}

fn decode_key_material(tag: PublicKeyAlgorithmTag, _bytes: &[u8]) -> io::Result<Box<dyn Params>> {
    match tag {
        #[cfg(feature = "rsa")]
        PublicKeyAlgorithmTag::RsaGeneral
        | PublicKeyAlgorithmTag::RsaEncrypt
        | PublicKeyAlgorithmTag::RsaSign => rsa::decode(_bytes),
        #[cfg(feature = "cfrg-curves")]
        PublicKeyAlgorithmTag::Ed25519 => curve25519::decode_ed25519(_bytes),
        #[cfg(feature = "cfrg-curves")]
        PublicKeyAlgorithmTag::X25519 => curve25519::decode_x25519(_bytes),
        _ => Err(unsupported_algorithm(tag)),
    }
}

fn unsupported_algorithm(tag: PublicKeyAlgorithmTag) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("unsupported OpenPGP public key algorithm {}", u8::from(tag)),
    )
}
