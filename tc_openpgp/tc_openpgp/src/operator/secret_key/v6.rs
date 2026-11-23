use std::io::{self, Read, Write};

use rand::rngs::SysRng;
use rand_core::TryRng;
use tc_algo::{
    Algo,
    params::{
        cipher::AeadParamsOwned,
        key::{Ed25519PrivateKey, X25519PrivateKey, X25519PublicKey},
    },
};
use tc_openpgp_packet::{
    BodyLength, DecodingConfig, EncodingConfig, PacketTag, PgpReader, PgpWrite, PgpWriter,
    PublicKeyAlgorithmTag, PublicKeyPacket, PublicKeyVersion,
};
use tc_pwhash::argon2::{Argon2, Argon2ParamsRef, Argon2Type};
use tc_zeroize::Zeroizing;

use super::{PgpSecretKeyProvider, PgpUnlockedSecretKey, SecretKeyLimits};
use crate::{
    PgpCertificate, PgpCertificateProvider, PgpKeyPair, PgpPrivateKey, PgpPublicKey,
    operator::{
        certificate::{V6Certificates, encode_with_keys},
        detached_signature::matching_ed25519_key,
        kdf::hkdf,
        serializer::{decode_key_packet, public_key_packet},
    },
};

const PUBLIC_BODY_LEN: usize = 42;
const AEAD_USAGE: u8 = 253;
const OCB: u8 = 2;
const AES_256: u8 = 9;
const OCB_TAG_LEN: usize = 16;
const PROTECTION_LEN: usize = 38;
const ENCRYPTED_LEN: usize = 32 + OCB_TAG_LEN;
const SECRET_BODY_LEN: usize = PUBLIC_BODY_LEN + 2 + PROTECTION_LEN + ENCRYPTED_LEN;
const DEFAULT_COST: [u8; 3] = [3, 4, 16];

impl PgpSecretKeyProvider for V6Certificates {
    fn export(
        &self,
        certificate: &PgpCertificate,
        primary: &PgpKeyPair,
        subkeys: &[&PgpKeyPair],
        passphrase: &[u8],
        output: &mut dyn Write,
    ) -> io::Result<()> {
        if passphrase.is_empty() || subkeys.len() != certificate.subkeys().len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a nonempty passphrase and matching subkeys",
            ));
        }
        let mut validated = Vec::with_capacity(subkeys.len() + 1);
        validated.push(export_key(certificate.primary_key(), primary, false)?);
        for (certified, pair) in certificate.subkeys().iter().zip(subkeys) {
            validated.push(export_key(certified.key(), pair, true)?);
        }
        // Finish all protection before writing to the caller's output.
        let mut protected = validated
            .into_iter()
            .map(|(public, private, tag)| {
                lock(&*self.signatures.algo, &public, private, tag, passphrase)
            })
            .collect::<io::Result<Vec<_>>>()?
            .into_iter();
        encode_with_keys(certificate, output, |_, subkey, output| {
            let bytes = protected
                .next()
                .ok_or_else(|| io::Error::other("missing protected certificate key"))?;
            write_packet(output, secret_tag(subkey), &bytes)
        })
    }

    fn import(
        &self,
        mut input: &[u8],
        passphrase: &[u8],
        config: &DecodingConfig,
        limits: &SecretKeyLimits,
    ) -> io::Result<PgpUnlockedSecretKey> {
        let mut pending = Vec::new();
        let mut certificate_bytes = Vec::new();
        let mut first = true;
        while !input.is_empty() {
            let before = input;
            {
                let mut reader = PgpReader::new(&mut input);
                let (header, mut body) = reader.read_body(config)?;
                let tag = header.tag();
                match tag {
                    PacketTag::SecretKey | PacketTag::SecretSubkey
                        if first == (tag == PacketTag::SecretKey) =>
                    {
                        if pending.len() >= limits.max_keys {
                            return Err(invalid("too many protected keys"));
                        }
                        let locked = LockedKey::read(tag, header.body_length(), &mut body, limits)?;
                        let config = EncodingConfig::default();
                        if first {
                            locked.public.encode(&mut certificate_bytes, &config)?;
                        } else {
                            locked
                                .public
                                .encode_subkey(&mut certificate_bytes, &config)?;
                        }
                        pending.push(locked);
                    }
                    PacketTag::Signature | PacketTag::UserId | PacketTag::Padding if !first => {
                        io::copy(&mut body, &mut io::sink())?;
                    }
                    _ => return Err(invalid("unexpected packet in transferable secret key")),
                }
                if matches!(tag, PacketTag::SecretKey | PacketTag::SecretSubkey) {
                    first = false;
                    continue;
                }
            }
            certificate_bytes.extend_from_slice(&before[..before.len() - input.len()]);
        }

        let certificate = self.decode(
            &certificate_bytes,
            &DecodingConfig {
                header_format: None,
                ..*config
            },
        )?;
        let mut pending = pending.into_iter();
        let primary = pending
            .next()
            .ok_or_else(|| invalid("missing primary secret key"))?
            .unlock(&*self.signatures.algo, passphrase)?;
        let subkeys = pending
            .map(|key| key.unlock(&*self.signatures.algo, passphrase))
            .collect::<io::Result<_>>()?;
        Ok(PgpUnlockedSecretKey {
            certificate,
            primary,
            subkeys,
        })
    }
}

struct LockedKey {
    tag: PacketTag,
    public: PublicKeyPacket,
    protection: [u8; PROTECTION_LEN],
    encrypted: [u8; ENCRYPTED_LEN],
}

impl LockedKey {
    fn read(
        tag: PacketTag,
        len: BodyLength,
        body: &mut dyn Read,
        limits: &SecretKeyLimits,
    ) -> io::Result<Self> {
        if len != BodyLength::Fixed(SECRET_BODY_LEN as u32) {
            return Err(invalid("unexpected protected OpenPGP key packet length"));
        }
        let mut public = [0; PUBLIC_BODY_LEN];
        body.read_exact(&mut public)?;
        let expected = if tag == PacketTag::SecretKey {
            PublicKeyAlgorithmTag::Ed25519
        } else {
            PublicKeyAlgorithmTag::X25519
        };
        if public[0] != 6 || public[5] != u8::from(expected) || public[6..10] != [0, 0, 0, 32] {
            return Err(invalid("unsupported public portion of secret key packet"));
        }
        let creation_time = u32::from_be_bytes([public[1], public[2], public[3], public[4]]);
        let public = PublicKeyPacket::new(
            PublicKeyVersion::V6,
            creation_time,
            expected,
            public[10..].to_vec(),
        );

        let mut usage = [0; 2];
        body.read_exact(&mut usage)?;
        let mut protection = [0; PROTECTION_LEN];
        body.read_exact(&mut protection)?;
        if usage != [AEAD_USAGE, PROTECTION_LEN as u8]
            || !matches!(protection[0], 7..=9)
            || protection[1..4] != [OCB, 20, 4]
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "expected Argon2id and AES-OCB secret-key protection",
            ));
        }
        validate_cost([protection[20], protection[21], protection[22]], limits)?;
        let mut encrypted = [0; ENCRYPTED_LEN];
        body.read_exact(&mut encrypted)?;
        Ok(Self {
            tag,
            public,
            protection,
            encrypted,
        })
    }

    fn unlock(self, algo: &dyn Algo, passphrase: &[u8]) -> io::Result<PgpKeyPair> {
        let params = cipher_params(algo, &self.public, self.tag, &self.protection, passphrase)?;
        let plaintext = Zeroizing::new(
            algo.cipher()
                .decrypt_by_name("AES/OCB/NoPadding", &params, &self.encrypted)
                .map_err(|_| invalid("secret key authentication failed"))?,
        );
        let mut private = Zeroizing::new([0; 32]);
        if plaintext.len() != private.len() {
            return Err(invalid("incorrect secret key material length"));
        }
        private.copy_from_slice(&plaintext);
        let algorithm = self.public.algorithm();
        let public = decode_key_packet(&self.public)?;
        let key = match algorithm {
            PublicKeyAlgorithmTag::Ed25519 => {
                PgpPrivateKey::new(algorithm, Box::new(Ed25519PrivateKey::new(*private)))
            }
            _ => PgpPrivateKey::new(algorithm, Box::new(X25519PrivateKey::new(*private))),
        };
        let pair = PgpKeyPair::new(public, key);
        if self.tag == PacketTag::SecretKey {
            matching_ed25519_key(&pair)?;
        } else {
            matching_x25519_key(&pair)?;
        }
        Ok(pair)
    }
}

fn export_key<'a>(
    certified: &PgpPublicKey,
    pair: &'a PgpKeyPair,
    subkey: bool,
) -> io::Result<(PublicKeyPacket, &'a [u8; 32], PacketTag)> {
    let public = public_key_packet(pair.public())?;
    if public != public_key_packet(certified)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private key does not match the certificate",
        ));
    }
    let private = if subkey {
        matching_x25519_key(pair)?.k()
    } else {
        matching_ed25519_key(pair)?.k()
    };
    Ok((public, private, secret_tag(subkey)))
}

fn matching_x25519_key(pair: &PgpKeyPair) -> io::Result<&X25519PrivateKey> {
    let public = pair
        .public()
        .key()
        .as_any()
        .downcast_ref::<X25519PublicKey>();
    pair.private()
        .key()
        .as_any()
        .downcast_ref::<X25519PrivateKey>()
        .filter(|private| {
            pair.private().algorithm() == PublicKeyAlgorithmTag::X25519
                && public == Some(&private.generate_public_key())
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a matching X25519 key pair",
            )
        })
}

fn lock(
    algo: &dyn Algo,
    public: &PublicKeyPacket,
    private: &[u8; 32],
    tag: PacketTag,
    passphrase: &[u8],
) -> io::Result<Vec<u8>> {
    let mut protection = [0; PROTECTION_LEN];
    protection[..4].copy_from_slice(&[AES_256, OCB, 20, 4]);
    protection[20..23].copy_from_slice(&DEFAULT_COST);
    SysRng
        .try_fill_bytes(&mut protection[4..20])
        .map_err(io::Error::other)?;
    SysRng
        .try_fill_bytes(&mut protection[23..])
        .map_err(io::Error::other)?;
    let params = cipher_params(algo, public, tag, &protection, passphrase)?;
    let encrypted = algo
        .cipher()
        .encrypt_by_name("AES/OCB/NoPadding", &params, private)
        .map_err(io::Error::other)?;
    if encrypted.len() != ENCRYPTED_LEN {
        return Err(io::Error::other(
            "unexpected protected key ciphertext length",
        ));
    }
    let mut body = Vec::with_capacity(SECRET_BODY_LEN);
    public.write_body(&mut body)?;
    body.extend_from_slice(&[AEAD_USAGE, PROTECTION_LEN as u8]);
    body.extend_from_slice(&protection);
    body.extend_from_slice(&encrypted);
    Ok(body)
}

fn cipher_params(
    algo: &dyn Algo,
    public: &PublicKeyPacket,
    tag: PacketTag,
    protection: &[u8; PROTECTION_LEN],
    passphrase: &[u8],
) -> io::Result<AeadParamsOwned> {
    let key_len = 16 + 8 * usize::from(protection[0] - 7);
    let params = Argon2ParamsRef::new(Argon2Type::Argon2id, &protection[4..20])
        .with_iterations(u32::from(protection[20]))
        .with_parallelism(u32::from(protection[21]))
        .with_memory_kib(1 << protection[22]);
    let mut argon = Argon2::new();
    argon.init(&params).map_err(io::Error::other)?;
    let mut ikm = Zeroizing::new(vec![0; key_len]);
    argon
        .generate_bytes(passphrase, &mut ikm)
        .map_err(io::Error::other)?;
    aead_params(algo, public, tag, protection, &ikm)
}

fn aead_params(
    algo: &dyn Algo,
    public: &PublicKeyPacket,
    tag: PacketTag,
    protection: &[u8; PROTECTION_LEN],
    ikm: &[u8],
) -> io::Result<AeadParamsOwned> {
    let tag_octet = 0xc0 | u8::from(tag);
    let info = [tag_octet, 6, protection[0], OCB];
    let mut key = hkdf(algo, ikm, &[], &info, ikm.len())?;
    let mut aad = vec![tag_octet];
    public.write_body(&mut aad)?;
    Ok(AeadParamsOwned::new(
        std::mem::take(&mut *key),
        protection[23..].to_vec(),
        OCB_TAG_LEN,
        aad,
    ))
}

fn validate_cost([passes, lanes, log_memory]: [u8; 3], limits: &SecretKeyLimits) -> io::Result<()> {
    let memory = 1_u32
        .checked_shl(u32::from(log_memory))
        .ok_or_else(|| invalid("invalid Argon2id memory exponent"))?;
    if passes == 0
        || lanes == 0
        || memory < 8 * u32::from(lanes)
        || memory > limits.max_memory_kib
        || passes > limits.max_passes
    {
        return Err(invalid(
            "Argon2id parameters exceed import limits or are invalid",
        ));
    }
    Ok(())
}

fn write_packet(output: &mut dyn Write, tag: PacketTag, bytes: &[u8]) -> io::Result<()> {
    let mut writer = PgpWriter::new(output);
    let mut body = writer.write_body(tag, BodyLength::Fixed(SECRET_BODY_LEN as u32))?;
    body.write_all(bytes)?;
    body.finish()
}

fn secret_tag(subkey: bool) -> PacketTag {
    if subkey {
        PacketTag::SecretSubkey
    } else {
        PacketTag::SecretKey
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

    #[test]
    fn rfc_9580_locked_primary_key_authenticates_with_known_s2k_material() {
        // Appendix A.5 uses 2 GiB of Argon2 memory. Use its published S2K
        // output to test the packet fields, HKDF, associated data and OCB.
        let mut bytes: &[u8] = &[
            0x06, 0x63, 0x87, 0x7f, 0xe3, 0x1b, 0x00, 0x00, 0x00, 0x20, 0xf9, 0x4d, 0xa7, 0xbb,
            0x48, 0xd6, 0x0a, 0x61, 0xe5, 0x67, 0x70, 0x6a, 0x65, 0x87, 0xd0, 0x33, 0x19, 0x99,
            0xbb, 0x9d, 0x89, 0x1a, 0x08, 0x24, 0x2e, 0xad, 0x84, 0x54, 0x3d, 0xf8, 0x95, 0xa3,
            0xfd, 0x26, 0x09, 0x02, 0x14, 0x04, 0x5d, 0x6f, 0xd7, 0x1c, 0x9e, 0x09, 0x6d, 0x1e,
            0xb6, 0x91, 0x7b, 0x6e, 0x6e, 0x1e, 0xec, 0xae, 0x01, 0x04, 0x15, 0xb4, 0xa8, 0xa9,
            0x27, 0x4f, 0xab, 0xe6, 0x32, 0xf8, 0x75, 0xa7, 0x06, 0x59, 0x20, 0x21, 0x78, 0x25,
            0x8f, 0xa4, 0x84, 0xd8, 0x8b, 0x27, 0xf2, 0x20, 0xe3, 0xd2, 0xde, 0x02, 0x03, 0xca,
            0x0f, 0x1f, 0xee, 0xcb, 0x6b, 0x77, 0x53, 0x81, 0xe3, 0xe2, 0xd9, 0xb1, 0x48, 0x5c,
            0x22, 0x33, 0x8c, 0xa5, 0x51, 0xe0, 0x9a, 0x26, 0x3f, 0x22, 0xeb, 0x49, 0x92, 0xe9,
            0x67, 0x7a, 0x80, 0x58,
        ];
        let limits = SecretKeyLimits {
            max_memory_kib: 1 << 21,
            ..SecretKeyLimits::default()
        };
        let locked = LockedKey::read(
            PacketTag::SecretKey,
            BodyLength::Fixed(130),
            &mut bytes,
            &limits,
        )
        .unwrap();
        assert!(bytes.is_empty());
        let ikm = [
            0x83, 0x2b, 0xd2, 0x66, 0x2a, 0x5c, 0x2b, 0x25, 0x1e, 0xe3, 0xfc, 0x82, 0xae, 0xc3,
            0x49, 0xa7, 0x66, 0xca, 0x53, 0x90, 0x15, 0x88, 0x01, 0x33, 0x00, 0x2e, 0x5a, 0x21,
            0x96, 0x0b, 0x3b, 0xcf,
        ];
        let algo = DefaultAlgoBuilder::default().build();
        let params =
            aead_params(&*algo, &locked.public, locked.tag, &locked.protection, &ikm).unwrap();
        let plaintext = algo
            .cipher()
            .decrypt_by_name("AES/OCB/NoPadding", &params, &locked.encrypted)
            .unwrap();
        let key = Ed25519PrivateKey::new(plaintext.try_into().unwrap());
        assert_eq!(key.generate_public_key().a(), locked.public.key_material());
    }
}
