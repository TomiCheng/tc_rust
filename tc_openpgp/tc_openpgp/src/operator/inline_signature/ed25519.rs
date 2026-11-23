use std::io::{self, Read, Write};

use crate::{
    PgpKeyPair, PgpPublicKey,
    operator::{
        detached_signature::{
            DefaultDetachedSignatures, DocumentCanonicalizer, PgpDetachedSignatureProvider,
        },
        serializer::v6_fingerprint,
    },
};
use tc_openpgp_packet::{
    DecodingConfig, EncodingConfig, LiteralData, OnePassSignaturePacket, PgpRead, PgpWrite,
    PublicKeyAlgorithmTag, PublicKeyVersion, SignaturePacket, SignatureTypeId, SignatureVersion,
};

use super::PgpInlineSignatureProvider;

impl PgpInlineSignatureProvider for DefaultDetachedSignatures {
    fn sign(
        &self,
        keys: &PgpKeyPair,
        literal: &LiteralData,
        creation_time: u32,
        output: &mut dyn Write,
    ) -> io::Result<()> {
        let ed25519 = self.ed25519();
        let signature = ed25519.sign(keys, &mut literal.data(), creation_time)?;
        let fingerprint = v6_fingerprint(&*self.algo, keys.public())?;
        let header = OnePassSignaturePacket::new_v6(
            signature.signature_type(),
            signature.hash_algorithm(),
            signature.public_key_algorithm(),
            signature.salt().to_vec(),
            fingerprint,
            false,
        );
        let config = EncodingConfig::default();
        header.encode(output, &config)?;
        literal.encode(output, &config)?;
        signature.encode(output, &config)?;
        Ok(())
    }

    fn verify(
        &self,
        key: &PgpPublicKey,
        input: &mut dyn Read,
        config: &DecodingConfig,
    ) -> io::Result<LiteralData> {
        let header = OnePassSignaturePacket::decode(input, config)?;
        if header.another_follows()
            || key.version() != PublicKeyVersion::V6
            || key.algorithm() != PublicKeyAlgorithmTag::Ed25519
            || header.public_key_algorithm() != PublicKeyAlgorithmTag::Ed25519
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "expected a single v6 Ed25519 one-pass signature",
            ));
        }
        if header.fingerprint() != &v6_fingerprint(&*self.algo, key)? {
            return Err(invalid(
                "one-pass signer fingerprint does not match the supplied key",
            ));
        }
        let text = match header.signature_type() {
            SignatureTypeId::BINARY_DOCUMENT => false,
            SignatureTypeId::CANONICAL_TEXT_DOCUMENT => true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "expected a document signature",
                ));
            }
        };
        let ed25519 = self.ed25519();
        let (mut digest, digest_len) =
            ed25519.start_hash(header.hash_algorithm(), header.salt())?;
        let mut canonicalizer = DocumentCanonicalizer::default();
        let literal = LiteralData::decode_with_data(input, config, |bytes| {
            let bytes = if text {
                canonicalizer.convert(bytes)
            } else {
                bytes
            };
            digest.try_update(bytes).map_err(io::Error::other)
        })?;
        let signature = SignaturePacket::decode(input, config)?;
        if signature.version() != SignatureVersion::V6
            || signature.signature_type() != header.signature_type()
            || signature.hash_algorithm() != header.hash_algorithm()
            || signature.public_key_algorithm() != header.public_key_algorithm()
            || signature.salt() != header.salt()
        {
            return Err(invalid(
                "one-pass fields do not match the trailing signature",
            ));
        }
        let hash = ed25519.finish_hash(digest, digest_len, &signature)?;
        if !ed25519.verify_prehashed(key, &signature, &hash)? {
            return Err(invalid("OpenPGP inline signature verification failed"));
        }
        Ok(literal)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
