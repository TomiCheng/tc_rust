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
};

use super::PgpDetachedSignatureProvider;
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
        let public = public_key(keys.public())?;
        let private = keys
            .private()
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
            })?;
        let mut salt = vec![0; 32];
        SysRng.try_fill_bytes(&mut salt).map_err(io::Error::other)?;

        let fingerprint = v6_fingerprint(&*self.algo, keys.public())?;
        let mut hashed = vec![5, 0x82];
        hashed.extend_from_slice(&creation_time.to_be_bytes());
        hashed.extend_from_slice(&[34, 33, 6]);
        hashed.extend_from_slice(&fingerprint);
        let packet = SignaturePacket::new_v6(
            SignatureTypeId::BINARY_DOCUMENT,
            PublicKeyAlgorithmTag::Ed25519,
            HashAlgorithmTag::Sha512,
            salt,
        )
        .with_subpackets(hashed, Vec::new());
        let hash = self.hash_document(document, &packet)?;
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

    fn verify(
        &self,
        key: &PgpPublicKey,
        document: &mut dyn Read,
        signature: &SignaturePacket,
    ) -> io::Result<bool> {
        let public = public_key(key)?;
        if signature.public_key_algorithm() != PublicKeyAlgorithmTag::Ed25519 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "expected an Ed25519 signature",
            ));
        }
        if signature.signature().len() != 64 {
            return Err(invalid("incorrect Ed25519 signature length"));
        }
        let fingerprint = v6_fingerprint(&*self.algo, key)?;
        if !verify_hashed_subpackets(signature.hashed_subpackets(), &fingerprint)? {
            return Ok(false);
        }
        let hash = self.hash_document(document, signature)?;
        if hash_prefix(&hash)? != signature.hash_prefix() {
            return Ok(false);
        }
        let mut verifier = self.signer(public)?;
        verifier.update(&hash).map_err(crypto)?;
        verifier
            .verify_signature(signature.signature())
            .map_err(crypto)
    }
}

impl Ed25519DetachedSignatures {
    fn signer(&self, key: &dyn Params) -> io::Result<Box<dyn tc_algo::signer::Signer>> {
        let mut signer = self.algo.signer().get_by_name("Ed25519").map_err(crypto)?;
        signer.init(key).map_err(crypto)?;
        Ok(signer)
    }

    fn hash_document(
        &self,
        document: &mut dyn Read,
        packet: &SignaturePacket,
    ) -> io::Result<Vec<u8>> {
        let (name, salt_len, digest_len) = match packet.hash_algorithm() {
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
        if packet.salt().len() != salt_len {
            return Err(invalid("incorrect v6 signature salt length"));
        }
        let text = match packet.signature_type() {
            SignatureTypeId::BINARY_DOCUMENT => false,
            SignatureTypeId::CANONICAL_TEXT_DOCUMENT => true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "expected a document signature",
                ));
            }
        };
        let mut digest = self.algo.digest().get_by_name(name).map_err(crypto)?;
        digest.try_update(packet.salt()).map_err(crypto)?;
        hash_input(document, &mut *digest, text)?;
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

fn verify_hashed_subpackets(mut bytes: &[u8], fingerprint: &[u8; 32]) -> io::Result<bool> {
    let mut creation_seen = false;
    let mut fingerprint_seen = false;
    while !bytes.is_empty() {
        let size = match take(&mut bytes, 1)?[0] {
            first @ 0..=191 => usize::from(first),
            first @ 192..=254 => {
                ((usize::from(first) - 192) << 8) + usize::from(take(&mut bytes, 1)?[0]) + 192
            }
            255 => {
                let encoded = take(&mut bytes, 4)?
                    .try_into()
                    .map_err(|_| invalid("invalid signature subpacket length"))?;
                usize::try_from(u32::from_be_bytes(encoded))
                    .map_err(|_| invalid("invalid signature subpacket length"))?
            }
        };
        let (tag, value) = take(&mut bytes, size)?
            .split_first()
            .ok_or_else(|| invalid("empty signature subpacket"))?;
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
    Ok(true)
}

fn take<'a>(bytes: &mut &'a [u8], len: usize) -> io::Result<&'a [u8]> {
    let (field, rest) = bytes
        .split_at_checked(len)
        .ok_or_else(|| invalid("truncated signature subpacket"))?;
    *bytes = rest;
    Ok(field)
}

fn hash_input(input: &mut dyn Read, digest: &mut dyn Digest, text: bool) -> io::Result<()> {
    let mut bytes = [0; 4096];
    let mut canonical = Vec::new();
    let mut previous_cr = false;
    loop {
        let count = match input.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let mut chunk = &bytes[..count];
        if text {
            canonical.clear();
            for &byte in chunk {
                match byte {
                    b'\n' if previous_cr => {}
                    b'\r' | b'\n' => canonical.extend_from_slice(b"\r\n"),
                    _ => canonical.push(byte),
                }
                previous_cr = byte == b'\r';
            }
            chunk = &canonical;
        }
        digest.try_update(chunk).map_err(crypto)?;
    }
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
