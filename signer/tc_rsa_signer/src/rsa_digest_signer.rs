use alloc::{vec, vec::Vec};
use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use tc_asn1::{Asn1Error, Asn1Object, Encode, EncodingOptions};
use tc_asn1_x509::alg::{AlgorithmIdentifier, DigestInfo};
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
};
use tc_asym_encoding::Pkcs1Encoding;
use tc_constant_time::fixed_time_eq;
use tc_digest::Digest;
use tc_signer::{Signer, SignerInit};

use crate::RsaDigestSignerError;

/// BC's `RsaDigestSigner`: PKCS#1 v1.5 signatures of RFC 8017 §8.2. The message is hashed with
/// the digest `D`, named by `digest_algorithm` in a DER `DigestInfo`, padded as block type 1
/// and raised by the RSA engine `E`.
///
/// Verification also takes the `DigestInfo` with the parameters of the algorithm absent where
/// they are NULL, and NULL where they are absent, as BC does.
pub struct RsaDigestSigner<E, D> {
    engine: Pkcs1Encoding<E, NoDraws>,
    digest: D,
    digest_algorithm: AlgorithmIdentifier,
    mode: Option<Mode>,
}

#[derive(Clone, Copy)]
enum Mode {
    Signing,
    Verifying,
}

impl<E, D> RsaDigestSigner<E, D> {
    /// A signer to be initialized. `digest_algorithm` names `digest` in the `DigestInfo`, as
    /// `AlgorithmIdentifier::with_null` of the digest's OID does. Constant time.
    pub fn new(engine: E, digest: D, digest_algorithm: AlgorithmIdentifier) -> Self {
        Self {
            engine: Pkcs1Encoding::from_parts(engine, NoDraws),
            digest,
            digest_algorithm,
            mode: None,
        }
    }
}

impl<E: AsymmetricBlockCipher, D: Digest> RsaDigestSigner<E, D> {
    fn finish_hash(&mut self) -> Vec<u8> {
        let mut hash = vec![0; self.digest.digest_size()];
        self.digest.do_final(&mut hash);
        hash
    }
}

/// A private key signs and a public key verifies. Starts a new message. Fails with the
/// engine's error, which leaves the signer uninitialized. Variable time in the engine's
/// `init` only.
impl<E, D, P> SignerInit<P> for RsaDigestSigner<E, D>
where
    E: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>,
    D: Digest,
    P: AsymmetricKeyParams + ?Sized,
{
    type Error = RsaDigestSignerError<<E as AsymmetricBlockCipherInit<P>>::Error>;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.mode = None;
        self.digest.reset();
        let (mode, direction) = if params.is_private_key() {
            (Mode::Signing, CipherDirection::Encrypt)
        } else {
            (Mode::Verifying, CipherDirection::Decrypt)
        };
        self.engine
            .init(direction, params)
            .map_err(RsaDigestSignerError::Cipher)?;
        self.mode = Some(mode);
        Ok(())
    }
}

impl<E: AsymmetricBlockCipher, D: Digest> Signer for RsaDigestSigner<E, D> {
    type Error = RsaDigestSignerError<E::Error>;

    /// The length of the modulus. Panics before `init`. Constant time.
    fn max_signature_size(&self) -> usize {
        match self.mode.expect("the signer is initialized") {
            Mode::Signing => self.engine.output_block_size(),
            Mode::Verifying => self.engine.input_block_size(),
        }
    }

    /// Hashes `input`. Fails before `init`. Constant time, as the digest is.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.mode.ok_or(RsaDigestSignerError::NotInitialized)?;
        self.digest.update(input);
        Ok(())
    }

    /// Writes the signature, as long as the modulus, into `output`. Fails with a public key,
    /// or with `OutputTooShort` from the encoding for a short `output`. Constant time, apart
    /// from the engine: the `DigestInfo` varies only in public lengths.
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.mode {
            None => return Err(RsaDigestSignerError::NotInitialized),
            Some(Mode::Verifying) => return Err(RsaDigestSignerError::NotForSigning),
            Some(Mode::Signing) => {}
        }
        let hash = self.finish_hash();
        let block = der(&self.digest_algorithm, &hash).map_err(RsaDigestSignerError::Encoding)?;
        self.engine
            .process_block(&block, output)
            .map_err(RsaDigestSignerError::Cipher)
    }

    /// Whether `signature` signs the message: `false` for any signature the engine or the
    /// padding turns down. Fails with a private key. Variable time: only for public values,
    /// as the signature and the message are; the blocks are compared in constant time, as BC
    /// does.
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error> {
        match self.mode {
            None => return Err(RsaDigestSignerError::NotInitialized),
            Some(Mode::Signing) => return Err(RsaDigestSignerError::NotForVerifying),
            Some(Mode::Verifying) => {}
        }
        let hash = self.finish_hash();
        let mut block = vec![0; self.engine.output_block_size()];
        let Ok(len) = self.engine.process_block(signature, &mut block) else {
            return Ok(false);
        };
        let block = &block[..len];
        let expected =
            der(&self.digest_algorithm, &hash).map_err(RsaDigestSignerError::Encoding)?;
        if fixed_time_eq(block, &expected) {
            return Ok(true);
        }
        match alternative(&self.digest_algorithm) {
            Some(algorithm) => {
                let expected = der(&algorithm, &hash).map_err(RsaDigestSignerError::Encoding)?;
                Ok(fixed_time_eq(block, &expected))
            }
            None => Ok(false),
        }
    }

    /// Starts a new message, keeping the key. Constant time.
    fn reset(&mut self) {
        self.digest.reset();
    }
}

fn der(algorithm: &AlgorithmIdentifier, hash: &[u8]) -> Result<Vec<u8>, Asn1Error> {
    DigestInfo::new(algorithm.clone(), hash).encode_to_vec(&EncodingOptions::DER)
}

// BC's `TryGetAltAlgID`: absent parameters for NULL ones, and NULL for absent ones.
fn alternative(algorithm: &AlgorithmIdentifier) -> Option<AlgorithmIdentifier> {
    match algorithm.parameters() {
        None => Some(AlgorithmIdentifier::with_null(
            algorithm.algorithm().clone(),
        )),
        Some(Asn1Object::Null(_)) => Some(AlgorithmIdentifier::new(algorithm.algorithm().clone())),
        Some(_) => None,
    }
}

// The random source of the PKCS#1 encoding, which draws only to pad with a public key as
// block type 2. The signer pads with a private key, as block type 1, and verifies with a
// public one, so it never draws.
struct NoDraws;

impl TryRng for NoDraws {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        unreachable!("PKCS#1 block type 1 draws nothing")
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        unreachable!("PKCS#1 block type 1 draws nothing")
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Infallible> {
        unreachable!("PKCS#1 block type 1 draws nothing")
    }
}

impl TryCryptoRng for NoDraws {}
