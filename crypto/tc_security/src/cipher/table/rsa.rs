use core::error::Error;

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use tc_asn1::NamedOid;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_asym_encoding::Pkcs1Encoding;
use tc_buffered_cipher::BufferedAsymmetricBlockCipher;
use tc_rsa::{RsaBlindedEngine, RsaEngine, RsaKey};

use super::same_name;
use super::specs::PaddingSpec;
use crate::cipher::{Algorithm, AnyCipher, Mode, Padding};
#[cfg(any(
    feature = "md5",
    feature = "sha1",
    feature = "sha224",
    feature = "sha256",
    feature = "sha384",
    feature = "sha512"
))]
use crate::digest::Algorithm as DigestAlgorithm;
use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

pub(super) const NAME: &str = "RSA";

pub(super) const PADDINGS: &[PaddingSpec] = &[
    PaddingSpec {
        padding: Padding::NoPadding,
        names: &["NOPADDING"],
    },
    PaddingSpec {
        padding: Padding::Pkcs1,
        names: &["PKCS1PADDING", "PKCS1"],
    },
    #[cfg(feature = "md5")]
    PaddingSpec {
        padding: Padding::OaepMd5,
        names: &["OAEPWITHMD5ANDMGF1PADDING"],
    },
    #[cfg(feature = "sha1")]
    PaddingSpec {
        padding: Padding::OaepSha1,
        names: &[
            "OAEPWITHSHA1ANDMGF1PADDING",
            "OAEPWITHSHA-1ANDMGF1PADDING",
            "OAEPPADDING",
            "OAEP",
        ],
    },
    #[cfg(feature = "sha224")]
    PaddingSpec {
        padding: Padding::OaepSha224,
        names: &[
            "OAEPWITHSHA224ANDMGF1PADDING",
            "OAEPWITHSHA-224ANDMGF1PADDING",
        ],
    },
    #[cfg(feature = "sha256")]
    PaddingSpec {
        padding: Padding::OaepSha256,
        names: &[
            "OAEPWITHSHA256ANDMGF1PADDING",
            "OAEPWITHSHA-256ANDMGF1PADDING",
            "OAEPWITHSHA256ANDMGF1WITHSHA256PADDING",
            "OAEPWITHSHA-256ANDMGF1WITHSHA-256PADDING",
        ],
    },
    #[cfg(all(feature = "sha256", feature = "sha1"))]
    PaddingSpec {
        padding: Padding::OaepSha256Mgf1Sha1,
        names: &[
            "OAEPWITHSHA256ANDMGF1WITHSHA1PADDING",
            "OAEPWITHSHA-256ANDMGF1WITHSHA-1PADDING",
        ],
    },
    #[cfg(feature = "sha384")]
    PaddingSpec {
        padding: Padding::OaepSha384,
        names: &[
            "OAEPWITHSHA384ANDMGF1PADDING",
            "OAEPWITHSHA-384ANDMGF1PADDING",
        ],
    },
    #[cfg(feature = "sha512")]
    PaddingSpec {
        padding: Padding::OaepSha512,
        names: &[
            "OAEPWITHSHA512ANDMGF1PADDING",
            "OAEPWITHSHA-512ANDMGF1PADDING",
        ],
    },
    #[cfg(feature = "iso9796")]
    PaddingSpec {
        padding: Padding::Iso9796_1,
        names: &["ISO9796-1PADDING", "ISO9796-1"],
    },
];

const PKCS1_OIDS: &[NamedOid] = &[NamedOid::new(
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
    "1.2.840.113549.1.1.1",
    "rsaEncryption",
)];

#[cfg(feature = "sha1")]
const OAEP_OIDS: &[NamedOid] = &[NamedOid::new(
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07],
    "1.2.840.113549.1.1.7",
    "id-RSAES-OAEP",
)];

pub(super) fn oids(padding: Padding) -> &'static [NamedOid] {
    match padding {
        Padding::Pkcs1 => PKCS1_OIDS,
        #[cfg(feature = "sha1")]
        Padding::OaepSha1 => OAEP_OIDS,
        _ => &[],
    }
}

pub(super) fn is_padding(padding: Padding) -> bool {
    PADDINGS.iter().any(|spec| spec.padding == padding)
}

pub(super) fn resolve(
    mode: Option<Mode>,
    padding: Option<Padding>,
) -> Option<(Option<Mode>, Option<Padding>)> {
    if !matches!(mode, None | Some(Mode::Ecb)) {
        return None;
    }
    let padding = padding.unwrap_or(Padding::NoPadding);
    is_padding(padding).then_some((None, Some(padding)))
}

pub(super) fn parse(
    mode: Option<&str>,
    padding: Option<&str>,
) -> Option<(Algorithm, Option<Mode>, Option<Padding>)> {
    if mode.is_some_and(|mode| !same_name("NONE", mode) && !same_name("ECB", mode)) {
        return None;
    }
    let padding = match padding {
        Some(name) => {
            PADDINGS
                .iter()
                .find(|spec| spec.names.iter().any(|known| same_name(known, name)))?
                .padding
        }
        None => Padding::NoPadding,
    };
    Some((Algorithm::Rsa, None, Some(padding)))
}

type Rng = UnwrapErr<SysRng>;

fn engine() -> RsaBlindedEngine<RsaEngine, Rng> {
    RsaBlindedEngine::from_parts(RsaEngine::new(), UnwrapErr(SysRng))
}

#[cfg(any(
    feature = "md5",
    feature = "sha1",
    feature = "sha224",
    feature = "sha256",
    feature = "sha384",
    feature = "sha512"
))]
fn oaep(
    mgf: crate::digest::Algorithm,
) -> tc_asym_encoding::OaepEncoding<RsaBlindedEngine<RsaEngine, Rng>, crate::digest::AnyDigest, Rng>
{
    tc_asym_encoding::OaepEncoding::from_parts(engine(), crate::digest::get(mgf), UnwrapErr(SysRng))
}

pub(super) fn create(padding: Padding) -> AnyCipher {
    match padding {
        Padding::NoPadding => wrap(engine()),
        Padding::Pkcs1 => wrap(Pkcs1Encoding::from_parts(engine(), UnwrapErr(SysRng))),
        #[cfg(feature = "md5")]
        Padding::OaepMd5 => wrap(oaep(DigestAlgorithm::Md5)),
        #[cfg(feature = "sha1")]
        Padding::OaepSha1 => wrap(oaep(DigestAlgorithm::Sha1)),
        #[cfg(feature = "sha224")]
        Padding::OaepSha224 => wrap(oaep(DigestAlgorithm::Sha224)),
        #[cfg(feature = "sha256")]
        Padding::OaepSha256 => wrap(oaep(DigestAlgorithm::Sha256)),
        #[cfg(all(feature = "sha256", feature = "sha1"))]
        Padding::OaepSha256Mgf1Sha1 => wrap(
            oaep(DigestAlgorithm::Sha1)
                .with_label_digest(crate::digest::get(DigestAlgorithm::Sha256), &[]),
        ),
        #[cfg(feature = "sha384")]
        Padding::OaepSha384 => wrap(oaep(DigestAlgorithm::Sha384)),
        #[cfg(feature = "sha512")]
        Padding::OaepSha512 => wrap(oaep(DigestAlgorithm::Sha512)),
        #[cfg(feature = "iso9796")]
        Padding::Iso9796_1 => wrap(tc_asym_iso9796::Iso9796d1Encoding::new(UnwrapErr(SysRng))),
        _ => unreachable!("RSA entries only use RSA paddings"),
    }
}

fn wrap<C>(cipher: C) -> AnyCipher
where
    C: AsymmetricBlockCipher + AsymmetricBlockCipherInit<RsaKey> + 'static,
    <C as AsymmetricBlockCipher>::Error: Error + Send + Sync + 'static,
    <C as AsymmetricBlockCipherInit<RsaKey>>::Error: Error + Send + Sync + 'static,
{
    AnyCipher::new(BufferedAsymmetricBlockCipher::new(RsaKeyInit(cipher)))
}

struct RsaKeyInit<C>(C);

impl<C: AsymmetricBlockCipher> AsymmetricBlockCipher for RsaKeyInit<C> {
    type Error = C::Error;

    fn input_block_size(&self) -> usize {
        self.0.input_block_size()
    }

    fn output_block_size(&self) -> usize {
        self.0.output_block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.process_block(input, output)
    }
}

impl<C> AsymmetricBlockCipherInit<AnyParams> for RsaKeyInit<C>
where
    C: AsymmetricBlockCipherInit<RsaKey>,
    C::Error: Error + Send + Sync + 'static,
{
    type Error = AnyError;

    fn init(&mut self, direction: CipherDirection, params: &AnyParams) -> Result<(), AnyError> {
        let AnyParams::Rsa { key } = params else {
            return Err(AnyError::new(SecurityError::WrongParams));
        };
        self.0.init(direction, key).map_err(AnyError::new)
    }
}
