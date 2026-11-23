use std::io::{self, Read, Write};

use tc_openpgp_packet::{
    BodyLength, DecodingConfig, EncodingConfig, PacketTag, PgpRead, PgpReader, PgpWrite, PgpWriter,
    PublicKeyAlgorithmTag, PublicKeyPacket, PublicKeyVersion, SignaturePacket, SignatureTypeId,
};

use super::{PgpCertificate, PgpCertificateProvider, PgpCertifiedSubkey, PgpCertifiedUserId};
use crate::{
    PgpKeyPair, PgpPublicKey,
    operator::{
        detached_signature::Ed25519DetachedSignatures,
        serializer::{decode_key_packet, public_key_packet},
    },
};

pub(crate) struct V6Certificates {
    pub(crate) signatures: Ed25519DetachedSignatures,
}

impl PgpCertificateProvider for V6Certificates {
    fn create(
        &self,
        primary: &PgpKeyPair,
        user_ids: &[&str],
        subkeys: &[&PgpPublicKey],
        creation_time: u32,
    ) -> io::Result<PgpCertificate> {
        let primary_packet = public_key_packet(primary.public())?;
        require_key(&primary_packet, PublicKeyAlgorithmTag::Ed25519)?;
        let primary_data = key_hash_input(&primary_packet)?;
        // Key Flags: certify and sign. Features: v2 SEIPD.
        let direct_signature = self.signatures.sign_data(
            primary,
            &mut primary_data.as_slice(),
            creation_time,
            SignatureTypeId::DIRECT_KEY,
            &[2, 0x9b, 0x03, 2, 30, 0x08],
        )?;
        let mut certified_ids = Vec::with_capacity(user_ids.len());
        for &value in user_ids {
            let data = user_id_hash_input(&primary_data, value)?;
            let signature = self.signatures.sign_data(
                primary,
                &mut data.as_slice(),
                creation_time,
                SignatureTypeId::DEFAULT_CERTIFICATION,
                &[],
            )?;
            certified_ids.push(PgpCertifiedUserId {
                value: value.to_owned(),
                signature,
            });
        }
        let mut certified_subkeys = Vec::with_capacity(subkeys.len());
        for &key in subkeys {
            let packet = public_key_packet(key)?;
            require_key(&packet, PublicKeyAlgorithmTag::X25519)?;
            let data = subkey_hash_input(&primary_data, &packet)?;
            // Key Flags: encrypt communications and storage.
            let signature = self.signatures.sign_data(
                primary,
                &mut data.as_slice(),
                creation_time,
                SignatureTypeId::SUBKEY_BINDING,
                &[2, 0x9b, 0x0c],
            )?;
            certified_subkeys.push(PgpCertifiedSubkey {
                key: decode_key_packet(&packet)?,
                signature,
            });
        }
        Ok(PgpCertificate {
            primary_key: decode_key_packet(&primary_packet)?,
            direct_signature,
            user_ids: certified_ids,
            subkeys: certified_subkeys,
        })
    }

    fn encode_to(&self, certificate: &PgpCertificate, output: &mut dyn Write) -> io::Result<()> {
        encode_with_keys(certificate, output, |key, subkey, output| {
            let config = EncodingConfig::default();
            let packet = public_key_packet(key)?;
            if subkey {
                packet.encode_subkey(output, &config)?;
            } else {
                packet.encode(output, &config)?;
            }
            Ok(())
        })
    }

    fn decode(&self, mut bytes: &[u8], config: &DecodingConfig) -> io::Result<PgpCertificate> {
        let primary_packet = PublicKeyPacket::decode(&mut bytes, config)?;
        require_key(&primary_packet, PublicKeyAlgorithmTag::Ed25519)?;
        let primary_key = decode_key_packet(&primary_packet)?;
        let primary_data = key_hash_input(&primary_packet)?;
        let direct_signature = SignaturePacket::decode(&mut bytes, config)?;
        self.verify(
            &primary_key,
            &primary_data,
            &direct_signature,
            direct_signature.signature_type() == SignatureTypeId::DIRECT_KEY,
        )?;

        let mut user_ids = Vec::new();
        while next_tag(bytes, config)? == Some(PacketTag::UserId) {
            let value = {
                let mut reader = PgpReader::new(&mut bytes);
                let (header, mut body) = reader.read_body(config)?;
                if !matches!(header.body_length(), BodyLength::Fixed(_)) {
                    return Err(invalid("User ID packet must have a definite length"));
                }
                let mut value = Vec::new();
                body.read_to_end(&mut value)?;
                String::from_utf8(value).map_err(|_| invalid("User ID is not UTF-8"))?
            };
            let data = user_id_hash_input(&primary_data, &value)?;
            let signature = SignaturePacket::decode(&mut bytes, config)?;
            self.verify(
                &primary_key,
                &data,
                &signature,
                matches!(signature.signature_type().id(), 0x10..=0x13),
            )?;
            user_ids.push(PgpCertifiedUserId { value, signature });
        }

        let mut subkeys = Vec::new();
        while next_tag(bytes, config)? == Some(PacketTag::PublicSubkey) {
            let packet = PublicKeyPacket::decode_subkey(&mut bytes, config)?;
            require_key(&packet, PublicKeyAlgorithmTag::X25519)?;
            let data = subkey_hash_input(&primary_data, &packet)?;
            let signature = SignaturePacket::decode(&mut bytes, config)?;
            self.verify(
                &primary_key,
                &data,
                &signature,
                signature.signature_type() == SignatureTypeId::SUBKEY_BINDING,
            )?;
            subkeys.push(PgpCertifiedSubkey {
                key: decode_key_packet(&packet)?,
                signature,
            });
        }
        if next_tag(bytes, config)? == Some(PacketTag::Padding) {
            let mut reader = PgpReader::new(&mut bytes);
            let (header, mut body) = reader.read_body(config)?;
            if !matches!(header.body_length(), BodyLength::Fixed(_)) {
                return Err(invalid("padding packet must have a definite length"));
            }
            io::copy(&mut body, &mut io::sink())?;
        }
        if !bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unexpected packet in v6 certificate",
            ));
        }
        Ok(PgpCertificate {
            primary_key,
            direct_signature,
            user_ids,
            subkeys,
        })
    }
}

pub(in crate::operator) fn encode_with_keys(
    certificate: &PgpCertificate,
    output: &mut dyn Write,
    mut write_key: impl FnMut(&PgpPublicKey, bool, &mut dyn Write) -> io::Result<()>,
) -> io::Result<()> {
    let config = EncodingConfig::default();
    write_key(certificate.primary_key(), false, output)?;
    certificate.direct_signature.encode(output, &config)?;
    for id in certificate.user_ids() {
        let bytes = id.value.as_bytes();
        let mut writer = PgpWriter::new(&mut *output);
        let mut body =
            writer.write_body(PacketTag::UserId, BodyLength::Fixed(user_id_len(bytes)?))?;
        body.write_all(bytes)?;
        body.finish()?;
        id.signature.encode(output, &config)?;
    }
    for subkey in certificate.subkeys() {
        write_key(subkey.key(), true, output)?;
        subkey.signature.encode(output, &config)?;
    }
    Ok(())
}

impl V6Certificates {
    fn verify(
        &self,
        key: &PgpPublicKey,
        data: &[u8],
        signature: &SignaturePacket,
        expected_type: bool,
    ) -> io::Result<()> {
        if !expected_type {
            return Err(invalid("unexpected certificate signature type"));
        }
        if !self
            .signatures
            .verify_data(key, &mut &*data, signature, false)?
        {
            return Err(invalid("certificate signature verification failed"));
        }
        Ok(())
    }
}

fn next_tag(input: &[u8], config: &DecodingConfig) -> io::Result<Option<PacketTag>> {
    if input.is_empty() {
        return Ok(None);
    }
    let mut reader = PgpReader::new(input);
    let (header, _) = reader.read_body(config)?;
    Ok(Some(header.tag()))
}

fn require_key(packet: &PublicKeyPacket, algorithm: PublicKeyAlgorithmTag) -> io::Result<()> {
    if packet.version() != PublicKeyVersion::V6 || packet.algorithm() != algorithm {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported key in v6 certificate",
        ));
    }
    Ok(())
}

fn key_hash_input(key: &PublicKeyPacket) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    key.write_fingerprint_input(&mut data)?;
    Ok(data)
}

fn subkey_hash_input(primary: &[u8], subkey: &PublicKeyPacket) -> io::Result<Vec<u8>> {
    let mut data = primary.to_vec();
    subkey.write_fingerprint_input(&mut data)?;
    Ok(data)
}

fn user_id_hash_input(primary: &[u8], id: &str) -> io::Result<Vec<u8>> {
    let bytes = id.as_bytes();
    let len = user_id_len(bytes)?;
    let mut data = primary.to_vec();
    data.push(0xb4);
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(bytes);
    Ok(data)
}

fn user_id_len(bytes: &[u8]) -> io::Result<u32> {
    u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "User ID is too long"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
