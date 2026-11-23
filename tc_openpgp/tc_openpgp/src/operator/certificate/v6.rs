use std::{
    collections::HashSet,
    io::{self, Read, Write},
};

use tc_openpgp_packet::{
    BodyLength, DecodingConfig, EncodingConfig, PacketTag, PgpRead, PgpReader, PgpWrite, PgpWriter,
    PublicKeyAlgorithmTag, PublicKeyPacket, PublicKeyVersion, SignaturePacket, SignatureTypeId,
};

use super::{
    PgpCertificate, PgpCertificateProvider, PgpCertifiedSubkey, PgpCertifiedUserId,
    PgpKeyRevocationReason, policy::KeySignature,
};
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
        let mut seen = HashSet::new();
        for &key in subkeys {
            let packet = public_key_packet(key)?;
            require_key(&packet, PublicKeyAlgorithmTag::X25519)?;
            if !seen.insert(packet.key_material().to_vec()) {
                return Err(invalid("duplicate encryption subkey"));
            }
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
                signatures: vec![KeySignature::new(signature)?],
                revocations: Vec::new(),
            });
        }
        Ok(PgpCertificate {
            primary_key: decode_key_packet(&primary_packet)?,
            direct_signatures: vec![KeySignature::new(direct_signature)?],
            revocations: Vec::new(),
            user_ids: certified_ids,
            subkeys: certified_subkeys,
        })
    }

    fn revoke_primary(
        &self,
        certificate: &mut PgpCertificate,
        primary: &PgpKeyPair,
        reason: PgpKeyRevocationReason,
        creation_time: u32,
    ) -> io::Result<()> {
        let packet = matching_primary(certificate, primary)?;
        if creation_time < packet.creation_time() {
            return Err(invalid("revocation predates the primary key"));
        }
        let data = key_hash_input(&packet)?;
        let revocation = self.sign_revocation(
            primary,
            &data,
            SignatureTypeId::KEY_REVOCATION,
            reason,
            creation_time,
        )?;
        certificate.revocations.push(revocation);
        Ok(())
    }

    fn revoke_subkey(
        &self,
        certificate: &mut PgpCertificate,
        primary: &PgpKeyPair,
        subkey_index: usize,
        reason: PgpKeyRevocationReason,
        creation_time: u32,
    ) -> io::Result<()> {
        let packet = matching_primary(certificate, primary)?;
        let subkey = certificate
            .subkeys
            .get_mut(subkey_index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid subkey index"))?;
        if creation_time < packet.creation_time().max(subkey.key.creation_time()) {
            return Err(invalid("revocation predates the primary key or subkey"));
        }
        let data = subkey_hash_input(&key_hash_input(&packet)?, &public_key_packet(&subkey.key)?)?;
        let revocation = self.sign_revocation(
            primary,
            &data,
            SignatureTypeId::SUBKEY_REVOCATION,
            reason,
            creation_time,
        )?;
        subkey.revocations.push(revocation);
        Ok(())
    }

    fn apply_primary_revocation(
        &self,
        certificate: &mut PgpCertificate,
        mut bytes: &[u8],
        config: &DecodingConfig,
    ) -> io::Result<()> {
        let key = PublicKeyPacket::decode(&mut bytes, config)?;
        if key != public_key_packet(certificate.primary_key())? {
            return Err(invalid("revocation names a different primary key"));
        }
        let packet = SignaturePacket::decode(&mut bytes, config)?;
        if !bytes.is_empty() {
            return Err(invalid("unexpected data after primary-key revocation"));
        }
        let data = key_hash_input(&key)?;
        self.verify(
            certificate.primary_key(),
            &data,
            &packet,
            packet.signature_type() == SignatureTypeId::KEY_REVOCATION,
        )?;
        let revocation = KeySignature::new(packet)?;
        if !certificate
            .revocations
            .iter()
            .any(|old| old.packet == revocation.packet)
        {
            certificate.revocations.push(revocation);
        }
        Ok(())
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
        let (direct_signatures, revocations) = self.read_key_signatures(
            &mut bytes,
            config,
            &primary_key,
            &primary_data,
            SignatureTypeId::DIRECT_KEY,
            SignatureTypeId::KEY_REVOCATION,
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
        let mut seen = HashSet::new();
        while next_tag(bytes, config)? == Some(PacketTag::PublicSubkey) {
            let packet = PublicKeyPacket::decode_subkey(&mut bytes, config)?;
            require_key(&packet, PublicKeyAlgorithmTag::X25519)?;
            if !seen.insert(packet.key_material().to_vec()) {
                return Err(invalid("duplicate encryption subkey"));
            }
            let data = subkey_hash_input(&primary_data, &packet)?;
            let (signatures, revocations) = self.read_key_signatures(
                &mut bytes,
                config,
                &primary_key,
                &data,
                SignatureTypeId::SUBKEY_BINDING,
                SignatureTypeId::SUBKEY_REVOCATION,
            )?;
            subkeys.push(PgpCertifiedSubkey {
                key: decode_key_packet(&packet)?,
                signatures,
                revocations,
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
            direct_signatures,
            revocations,
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
    for signature in certificate
        .revocations
        .iter()
        .chain(&certificate.direct_signatures)
    {
        signature.packet.encode(output, &config)?;
    }
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
        for signature in subkey.revocations.iter().chain(&subkey.signatures) {
            signature.packet.encode(output, &config)?;
        }
    }
    Ok(())
}

impl V6Certificates {
    fn sign_revocation(
        &self,
        primary: &PgpKeyPair,
        mut data: &[u8],
        kind: SignatureTypeId,
        reason: PgpKeyRevocationReason,
        creation_time: u32,
    ) -> io::Result<KeySignature> {
        let packet = self.signatures.sign_data(
            primary,
            &mut data,
            creation_time,
            kind,
            &[2, 29, reason as u8],
        )?;
        KeySignature::new(packet)
    }

    fn read_key_signatures(
        &self,
        bytes: &mut &[u8],
        config: &DecodingConfig,
        primary: &PgpPublicKey,
        data: &[u8],
        binding_type: SignatureTypeId,
        revocation_type: SignatureTypeId,
    ) -> io::Result<(Vec<KeySignature>, Vec<KeySignature>)> {
        let mut signatures = Vec::new();
        let mut revocations = Vec::new();
        while next_tag(bytes, config)? == Some(PacketTag::Signature) {
            let packet = SignaturePacket::decode(bytes, config)?;
            let kind = packet.signature_type();
            let target = if kind == binding_type {
                &mut signatures
            } else if kind == revocation_type && signatures.is_empty() {
                &mut revocations
            } else {
                return Err(invalid("unexpected or out-of-order key signature"));
            };
            self.verify(primary, data, &packet, true)?;
            target.push(KeySignature::new(packet)?);
        }
        if signatures.is_empty() {
            return Err(invalid("missing direct-key or subkey binding signature"));
        }
        Ok((signatures, revocations))
    }

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

fn matching_primary(
    certificate: &PgpCertificate,
    pair: &PgpKeyPair,
) -> io::Result<PublicKeyPacket> {
    let packet = public_key_packet(certificate.primary_key())?;
    if public_key_packet(pair.public())? != packet {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "key pair does not match the certificate primary key",
        ));
    }
    Ok(packet)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tc_algo::{
        AlgoBuilder, DefaultAlgoBuilder,
        params::key::{Ed25519PrivateKey, X25519PrivateKey},
    };

    use super::*;
    use crate::{PgpEncryptionPurpose, PgpPrivateKey};

    #[test]
    fn latest_current_self_signature_controls_expiration_and_flags() {
        let algorithm = PublicKeyAlgorithmTag::Ed25519;
        let secret = Ed25519PrivateKey::new([1; 32]);
        let pair = PgpKeyPair::new(
            PgpPublicKey::new_with_metadata(
                algorithm,
                Box::new(secret.generate_public_key()),
                PublicKeyVersion::V6,
                100,
            ),
            PgpPrivateKey::new(algorithm, Box::new(secret)),
        );
        let subkey = PgpPublicKey::new_with_metadata(
            PublicKeyAlgorithmTag::X25519,
            Box::new(X25519PrivateKey::new([2; 32]).generate_public_key()),
            PublicKeyVersion::V6,
            110,
        );
        let provider = V6Certificates {
            signatures: Ed25519DetachedSignatures {
                algo: Arc::from(DefaultAlgoBuilder::default().build()),
            },
        };
        let mut certificate = provider.create(&pair, &[], &[&subkey], 120).unwrap();
        let primary_data = key_hash_input(&public_key_packet(pair.public()).unwrap()).unwrap();
        let subkey_data =
            subkey_hash_input(&primary_data, &public_key_packet(&subkey).unwrap()).unwrap();

        // The primary key expires at 170, relative to key creation.
        let signed = provider
            .signatures
            .sign_data(
                &pair,
                &mut primary_data.as_slice(),
                130,
                SignatureTypeId::DIRECT_KEY,
                &[2, 0x9b, 0x02, 5, 0x89, 0, 0, 0, 70],
            )
            .unwrap();
        certificate
            .direct_signatures
            .push(KeySignature::new(signed).unwrap());

        // From 135 to 154 the new binding permits storage only. The old
        // binding becomes current again when the new signature itself expires.
        let signed = provider
            .signatures
            .sign_data(
                &pair,
                &mut subkey_data.as_slice(),
                135,
                SignatureTypeId::SUBKEY_BINDING,
                &[2, 0x9b, 0x08, 5, 0x83, 0, 0, 0, 20],
            )
            .unwrap();
        certificate.subkeys[0]
            .signatures
            .push(KeySignature::new(signed).unwrap());

        // This binding expires the subkey at 165, even though an older
        // binding had granted unlimited lifetime.
        let signed = provider
            .signatures
            .sign_data(
                &pair,
                &mut subkey_data.as_slice(),
                160,
                SignatureTypeId::SUBKEY_BINDING,
                &[2, 0x9b, 0x04, 5, 0x89, 0, 0, 0, 55],
            )
            .unwrap();
        certificate.subkeys[0]
            .signatures
            .push(KeySignature::new(signed).unwrap());

        let bytes = provider.encode(&certificate).unwrap();
        let certificate = provider.decode(&bytes, &DecodingConfig::default()).unwrap();
        let comms = PgpEncryptionPurpose::Communications;
        let storage = PgpEncryptionPurpose::Storage;
        assert!(certificate.encryption_key_at(119, comms).is_none());
        assert!(certificate.encryption_key_at(134, comms).is_some());
        assert!(certificate.encryption_key_at(135, comms).is_none());
        assert!(certificate.encryption_key_at(135, storage).is_some());
        assert!(certificate.encryption_key_at(154, storage).is_some());
        assert!(certificate.encryption_key_at(155, comms).is_some());
        assert!(certificate.encryption_key_at(164, comms).is_some());
        assert!(certificate.encryption_key_at(165, comms).is_none());
        assert!(certificate.signing_key_at(169).is_some());
        assert!(certificate.signing_key_at(170).is_none());
    }
}
