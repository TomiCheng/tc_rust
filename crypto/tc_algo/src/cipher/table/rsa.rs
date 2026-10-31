use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use tc_asn1::NamedOid;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_asym_encoding::{OaepEncoding, Pkcs1Encoding};
use tc_buffered_cipher::{BufferedAsymmetricBlockCipher, BufferedCipher, BufferedCipherInit};
use tc_digest::Digest;
use tc_rsa::{RsaBlindedEngine, RsaEngine, RsaKey};
use tc_sha::{Sha1Digest, Sha224Digest, Sha256Digest, Sha384Digest, Sha512Digest};

use super::specs::{AsymmetricPaddingKind, AsymmetricSpec};
use crate::cipher::classify::Classify;
use crate::cipher::dyn_cipher::{DynCipher, Mapped};
use crate::cipher::init_params::InitParams;
use crate::params::{AnyKeyParams, AnyPrivateKey, AnyPublicKey};

type Rng = UnwrapErr<SysRng>;

// Blinded, as Bouncy Castle's CipherUtilities builds RSA, so that the private power never works
// on the ciphertext itself
type Engine = RsaBlindedEngine<RsaEngine, Rng>;

fn engine() -> Engine {
    RsaBlindedEngine::from_parts(RsaEngine::new(), UnwrapErr(SysRng))
}

fn boxed<T>(cipher: T) -> Box<dyn DynCipher>
where
    T: BufferedCipher + BufferedCipherInit<RsaKey> + Send + 'static,
    <T as BufferedCipher>::Error: Classify + core::error::Error + Send + Sync + 'static,
    <T as BufferedCipherInit<RsaKey>>::Error: Classify + core::error::Error + Send + Sync + 'static,
{
    Box::new(Mapped::<T, RsaKey>::new(cipher))
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
        AsymmetricPaddingKind::Iso9796d1 => boxed(BufferedAsymmetricBlockCipher::new(
            tc_asym_iso9796::Iso9796d1Encoding::new(UnwrapErr(SysRng)),
        )),
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

// Either key, in either direction, as in Bouncy Castle; the variant must agree with the key it
// holds, so that a private key never passes for a public one
fn key(key: &AnyKeyParams) -> Option<InitParams> {
    match key {
        AnyKeyParams::Public(AnyPublicKey::Rsa(key)) if !key.is_private_key() => {
            Some(InitParams::Rsa(key.clone()))
        }
        AnyKeyParams::Private(AnyPrivateKey::Rsa(key)) if key.is_private_key() => {
            Some(InitParams::Rsa(key.clone()))
        }
        _ => None,
    }
}

macro_rules! pkcs1_oid {
    ($arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, $arc],
            $dotted,
            $name,
        )
    };
}

// The OIDs follow Bouncy Castle: rsaEncryption is PKCS#1 v1.5, and id-RSAES-OAEP is OAEP with
// SHA-1, the default of its parameters
pub(super) const RSA: AsymmetricSpec = AsymmetricSpec {
    names: &["RSA"],
    paddings: &[
        AsymmetricPaddingKind::NoPadding,
        AsymmetricPaddingKind::Pkcs1,
        #[cfg(feature = "rsa-iso9796")]
        AsymmetricPaddingKind::Iso9796d1,
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
    oids: &[
        (
            AsymmetricPaddingKind::Pkcs1,
            &[pkcs1_oid!(0x01, "1.2.840.113549.1.1.1", "rsaEncryption")],
        ),
        (
            AsymmetricPaddingKind::OaepSha1,
            &[pkcs1_oid!(0x07, "1.2.840.113549.1.1.7", "id-RSAES-OAEP")],
        ),
    ],
};
