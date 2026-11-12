use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_asym_encoding::{OaepEncoding, Pkcs1Encoding};
use tc_buffered_cipher::{BufferedAsymmetricBlockCipher, BufferedCipher, BufferedCipherInit};
use tc_digest::Digest;
use tc_elgamal::{ElGamalEngine, ElGamalError};
use tc_sha::{Sha1Digest, Sha224Digest, Sha256Digest, Sha384Digest, Sha512Digest};

use super::specs::{AsymmetricPaddingKind, AsymmetricSpec};
use crate::cipher::classify::Classify;
use crate::cipher::dyn_cipher::{DynCipher, Mapped};
use crate::cipher::init_params::{ElGamalKey, InitParams};
use crate::params::{AnyKeyParams, AnyPrivateKey, AnyPublicKey};

// The engine, taking either key through ElGamalKey: the public one encrypts, the private one
// decrypts, and the engine refuses either in the other direction
struct Engine(ElGamalEngine<UnwrapErr<SysRng>>);

impl AsymmetricBlockCipherInit<ElGamalKey> for Engine {
    type Error = ElGamalError;

    fn init(&mut self, direction: CipherDirection, key: &ElGamalKey) -> Result<(), ElGamalError> {
        match key {
            ElGamalKey::Public(key) => self.0.init(direction, key),
            ElGamalKey::Private(key) => self.0.init(direction, key),
        }
    }
}

impl AsymmetricBlockCipher for Engine {
    type Error = ElGamalError;

    fn input_block_size(&self) -> usize {
        self.0.input_block_size()
    }

    fn output_block_size(&self) -> usize {
        self.0.output_block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ElGamalError> {
        self.0.process_block(input, output)
    }
}

fn engine() -> Engine {
    Engine(ElGamalEngine::new(UnwrapErr(SysRng)))
}

fn boxed<T>(cipher: T) -> Box<dyn DynCipher>
where
    T: BufferedCipher + BufferedCipherInit<ElGamalKey> + Send + 'static,
    <T as BufferedCipher>::Error: Classify + core::error::Error + Send + Sync + 'static,
    <T as BufferedCipherInit<ElGamalKey>>::Error:
        Classify + core::error::Error + Send + Sync + 'static,
{
    Box::new(Mapped::<T, ElGamalKey>::new(cipher))
}

// OAEP with the one digest M for both the label and MGF1
fn oaep<M: Digest + Default + Send + 'static>() -> Box<dyn DynCipher> {
    let encoding = OaepEncoding::from_parts(engine(), M::default(), UnwrapErr(SysRng));
    boxed(BufferedAsymmetricBlockCipher::new(encoding))
}

fn create(padding: AsymmetricPaddingKind) -> Box<dyn DynCipher> {
    match padding {
        AsymmetricPaddingKind::NoPadding => boxed(BufferedAsymmetricBlockCipher::new(engine())),
        AsymmetricPaddingKind::Pkcs1 => boxed(BufferedAsymmetricBlockCipher::new(
            Pkcs1Encoding::from_parts(engine(), UnwrapErr(SysRng)),
        )),
        #[cfg(feature = "rsa-iso9796")]
        AsymmetricPaddingKind::Iso9796d1 => {
            unreachable!("the table pairs ISO 9796-1 with RSA alone")
        }
        #[cfg(feature = "md5")]
        AsymmetricPaddingKind::OaepMd5 => oaep::<tc_md::Md5Digest>(),
        AsymmetricPaddingKind::OaepSha1 => oaep::<Sha1Digest>(),
        AsymmetricPaddingKind::OaepSha224 => oaep::<Sha224Digest>(),
        AsymmetricPaddingKind::OaepSha256 => oaep::<Sha256Digest>(),
        AsymmetricPaddingKind::OaepSha256Mgf1Sha1 => {
            let encoding = OaepEncoding::from_parts(engine(), Sha1Digest::new(), UnwrapErr(SysRng))
                .with_label_digest(Sha256Digest::new(), &[]);
            boxed(BufferedAsymmetricBlockCipher::new(encoding))
        }
        AsymmetricPaddingKind::OaepSha384 => oaep::<Sha384Digest>(),
        AsymmetricPaddingKind::OaepSha512 => oaep::<Sha512Digest>(),
    }
}

fn key(key: &AnyKeyParams) -> Option<InitParams> {
    match key {
        AnyKeyParams::Public(AnyPublicKey::ElGamal(key)) => {
            Some(InitParams::ElGamal(ElGamalKey::Public(key.clone())))
        }
        AnyKeyParams::Private(AnyPrivateKey::ElGamal(key)) => {
            Some(InitParams::ElGamal(ElGamalKey::Private(key.clone())))
        }
        _ => None,
    }
}

// Every padding of RSA but ISO 9796-1, which reads an RSA modulus. Bouncy Castle gives ElGamal
// no OID
pub(super) const ELGAMAL: AsymmetricSpec = AsymmetricSpec {
    names: &["ELGAMAL"],
    paddings: &[
        AsymmetricPaddingKind::NoPadding,
        AsymmetricPaddingKind::Pkcs1,
        #[cfg(feature = "md5")]
        AsymmetricPaddingKind::OaepMd5,
        AsymmetricPaddingKind::OaepSha1,
        AsymmetricPaddingKind::OaepSha224,
        AsymmetricPaddingKind::OaepSha256,
        AsymmetricPaddingKind::OaepSha256Mgf1Sha1,
        AsymmetricPaddingKind::OaepSha384,
        AsymmetricPaddingKind::OaepSha512,
    ],
    create,
    key,
    oids: &[],
};
