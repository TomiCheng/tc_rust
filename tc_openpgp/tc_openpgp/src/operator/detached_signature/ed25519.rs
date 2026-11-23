use std::{
    io::{self, Read},
    sync::Arc,
};

use rand::rngs::SysRng;
use rand_core::TryRng;
use tc_algo::{
    Algo, AlgoError, Params,
    digest::Digest,
    params::key::{Ed25519PrivateKey, Ed25519PublicKey},
};
use tc_openpgp_packet::{
    HashAlgorithmTag, PublicKeyAlgorithmTag, PublicKeyVersion, SignaturePacket, SignatureTypeId,
    SignatureVersion,
};

use super::{PgpDetachedSignatureProvider, document_is_text, read_document};
use crate::operator::signature_subpacket::Subpackets;
use crate::{PgpKeyPair, PgpPublicKey, operator::serializer::v6_fingerprint};

pub(crate) struct Ed25519DetachedSignatures {
    pub(crate) algo: Arc<dyn Algo>,
}

impl PgpDetachedSignatureProvider for Ed25519DetachedSignatures {
    fn sign(
        &self,
        keys: &PgpKeyPair,
        document: &mut dyn Read,
        creation_time: u32,
    ) -> io::Result<SignaturePacket> {
        self.sign_data(
            keys,
            document,
            creation_time,
            SignatureTypeId::BINARY_DOCUMENT,
            &[],
        )
    }

    fn verify(
        &self,
        key: &PgpPublicKey,
        document: &mut dyn Read,
        signature: &SignaturePacket,
    ) -> io::Result<bool> {
        let text = document_is_text(signature)?;
        self.verify_data(key, document, signature, text)
    }
}

impl Ed25519DetachedSignatures {
    pub(in crate::operator) fn sign_data(
        &self,
        keys: &PgpKeyPair,
        document: &mut dyn Read,
        creation_time: u32,
        signature_type: SignatureTypeId,
        extra_subpackets: &[u8],
    ) -> io::Result<SignaturePacket> {
        let private = matching_private_key(keys)?;
        let mut salt = vec![0; 32];
        SysRng.try_fill_bytes(&mut salt).map_err(io::Error::other)?;

        let fingerprint = v6_fingerprint(&*self.algo, keys.public())?;
        let mut hashed = vec![5, 0x82];
        hashed.extend_from_slice(&creation_time.to_be_bytes());
        hashed.extend_from_slice(&[34, 33, 6]);
        hashed.extend_from_slice(&fingerprint);
        hashed.extend_from_slice(extra_subpackets);
        let packet = SignaturePacket::new_v6(
            signature_type,
            PublicKeyAlgorithmTag::Ed25519,
            HashAlgorithmTag::Sha512,
            salt,
        )
        .with_subpackets(hashed, Vec::new());
        let hash = self.hash_data(document, &packet, false)?;
        let mut signer = self.signer(private)?;
        signer.update(&hash).map_err(crypto)?;
        let signature = signer.sign().map_err(crypto)?;
        if signature.len() != 64 {
            return Err(io::Error::other(
                "Ed25519 provider returned an invalid signature length",
            ));
        }
        Ok(packet.with_signature(hash_prefix(&hash)?, signature))
    }

    pub(in crate::operator) fn verify_data(
        &self,
        key: &PgpPublicKey,
        document: &mut dyn Read,
        signature: &SignaturePacket,
        text: bool,
    ) -> io::Result<bool> {
        let Some(public) = self.verification_key(key, signature, None)? else {
            return Ok(false);
        };
        let hash = self.hash_data(document, signature, text)?;
        self.verify_hash(public, signature, &hash)
    }

    pub(in crate::operator) fn verify_prehashed(
        &self,
        key: &PgpPublicKey,
        signature: &SignaturePacket,
        hash: &[u8],
        recipient: Option<&[u8; 32]>,
    ) -> io::Result<bool> {
        let Some(public) = self.verification_key(key, signature, recipient)? else {
            return Ok(false);
        };
        self.verify_hash(public, signature, hash)
    }

    fn verification_key<'a>(
        &self,
        key: &'a PgpPublicKey,
        signature: &SignaturePacket,
        recipient: Option<&[u8; 32]>,
    ) -> io::Result<Option<&'a Ed25519PublicKey>> {
        let public = public_key(key)?;
        if signature.version() != SignatureVersion::V6
            || signature.public_key_algorithm() != PublicKeyAlgorithmTag::Ed25519
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "expected a v6 Ed25519 signature",
            ));
        }
        if signature.signature().len() != 64 {
            return Err(invalid("incorrect Ed25519 signature length"));
        }
        let fingerprint = v6_fingerprint(&*self.algo, key)?;
        Ok(verify_hashed_subpackets(signature, &fingerprint, recipient)?.then_some(public))
    }

    fn verify_hash(
        &self,
        public: &Ed25519PublicKey,
        signature: &SignaturePacket,
        hash: &[u8],
    ) -> io::Result<bool> {
        if hash_prefix(hash)? != signature.hash_prefix() {
            return Ok(false);
        }
        let mut verifier = self.signer(public)?;
        verifier.update(hash).map_err(crypto)?;
        verifier
            .verify_signature(signature.signature())
            .map_err(crypto)
    }
    fn signer(&self, key: &dyn Params) -> io::Result<Box<dyn tc_algo::signer::Signer>> {
        let mut signer = self.algo.signer().get_by_name("Ed25519").map_err(crypto)?;
        signer.init(key).map_err(crypto)?;
        Ok(signer)
    }

    fn hash_data(
        &self,
        document: &mut dyn Read,
        packet: &SignaturePacket,
        text: bool,
    ) -> io::Result<Vec<u8>> {
        let (mut digest, digest_len) = self.start_hash(packet.hash_algorithm(), packet.salt())?;
        read_document(document, text, |bytes| {
            digest.try_update(bytes).map_err(crypto)
        })?;
        self.finish_hash(digest, digest_len, packet)
    }

    pub(in crate::operator) fn start_hash(
        &self,
        algorithm: HashAlgorithmTag,
        salt: &[u8],
    ) -> io::Result<(Box<dyn Digest>, usize)> {
        let (name, salt_len, digest_len) = match algorithm {
            HashAlgorithmTag::Sha256 => ("SHA-256", 16, 32),
            HashAlgorithmTag::Sha384 => ("SHA-384", 24, 48),
            HashAlgorithmTag::Sha512 => ("SHA-512", 32, 64),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported Ed25519 signature hash",
                ));
            }
        };
        if salt.len() != salt_len {
            return Err(invalid("incorrect v6 signature salt length"));
        }
        let mut digest = self.algo.digest().get_by_name(name).map_err(crypto)?;
        digest.try_update(salt).map_err(crypto)?;
        Ok((digest, digest_len))
    }

    pub(in crate::operator) fn finish_hash(
        &self,
        mut digest: Box<dyn Digest>,
        digest_len: usize,
        packet: &SignaturePacket,
    ) -> io::Result<Vec<u8>> {
        let mut suffix = Vec::new();
        packet.write_hash_suffix(&mut suffix)?;
        digest.try_update(&suffix).map_err(crypto)?;
        let bytes = digest.finalize().map_err(crypto)?;
        if bytes.len() != digest_len {
            return Err(io::Error::other(
                "signature digest provider returned an invalid digest length",
            ));
        }
        Ok(bytes)
    }
}

pub(in crate::operator) fn matching_private_key(
    keys: &PgpKeyPair,
) -> io::Result<&Ed25519PrivateKey> {
    let public = public_key(keys.public())?;
    keys.private()
        .key()
        .as_any()
        .downcast_ref::<Ed25519PrivateKey>()
        .filter(|private| {
            keys.private().algorithm() == PublicKeyAlgorithmTag::Ed25519
                && &private.generate_public_key() == public
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a matching Ed25519 key pair",
            )
        })
}

fn public_key(key: &PgpPublicKey) -> io::Result<&Ed25519PublicKey> {
    if key.version() != PublicKeyVersion::V6 || key.algorithm() != PublicKeyAlgorithmTag::Ed25519 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only v6 Ed25519 signing keys are supported",
        ));
    }
    key.key()
        .as_any()
        .downcast_ref::<Ed25519PublicKey>()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Ed25519 public key material",
            )
        })
}

fn verify_hashed_subpackets(
    signature: &SignaturePacket,
    fingerprint: &[u8; 32],
    recipient: Option<&[u8; 32]>,
) -> io::Result<bool> {
    let certificate = matches!(signature.signature_type().id(), 0x10..=0x13 | 0x18 | 0x1f);
    let revocation = matches!(signature.signature_type().id(), 0x20 | 0x28);
    let mut creation_seen = false;
    let mut fingerprint_seen = false;
    let mut intended_match = false;
    for entry in Subpackets::new(signature.hashed_subpackets()) {
        let (tag, value) = entry?;
        match tag & 0x7f {
            2 if !creation_seen && value.len() == 4 => creation_seen = true,
            33 if !fingerprint_seen && value.len() == 33 && value[0] == 6 => {
                if value[1..] != fingerprint[..] {
                    return Ok(false);
                }
                fingerprint_seen = true;
            }
            2 | 33 => {
                return Err(invalid(
                    "malformed signature creation time or issuer fingerprint",
                ));
            }
            3 | 9 if certificate && value.len() == 4 => {}
            27 | 30 if certificate && !value.is_empty() => {}
            29 if revocation && !value.is_empty() => {}
            35 => {
                let Some(recipient) = recipient else {
                    return Ok(false);
                };
                if value.len() != 33 || value[0] != 6 {
                    return Err(invalid("invalid v6 intended recipient fingerprint"));
                }
                intended_match |= value[1..] == recipient[..];
            }
            _ if tag & 0x80 != 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported critical signature subpacket",
                ));
            }
            _ => {}
        }
    }
    if !creation_seen {
        return Err(invalid("missing hashed signature creation time"));
    }
    Ok(recipient.is_none() || intended_match)
}

fn hash_prefix(hash: &[u8]) -> io::Result<[u8; 2]> {
    let [a, b, ..] = hash else {
        return Err(io::Error::other("invalid signature digest length"));
    };
    Ok([*a, *b])
}

fn crypto(error: AlgoError) -> io::Error {
    io::Error::other(error)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
