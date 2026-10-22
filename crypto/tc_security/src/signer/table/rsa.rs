//! PKCS#1 v1.5 簽章，BC 的 `RsaDigestSigner`：名稱與 OID 照 BC 的 `SignerUtilities`。

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use tc_asn1::NamedOid;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_rsa::{RsaBlindedEngine, RsaEngine, RsaKey};
use tc_rsa_signer::RsaDigestSigner;

use crate::digest::{self, Algorithm};
use crate::params::AnyParams;
use crate::signer::{AnySigner, SignerEntry};

// RSA 由金鑰本身分辨私鑰或公鑰，所以簽章與驗章用同一個函式取金鑰
fn rsa_key(params: &AnyParams) -> Option<&RsaKey> {
    match params {
        AnyParams::Rsa { key } => Some(key),
        _ => None,
    }
}

// 同 BC 用 blinding 的引擎；DigestInfo 的演算法參數是 NULL
fn signer(algorithm: Algorithm) -> AnySigner {
    let oid = algorithm
        .entry()
        .oid()
        .expect("every digest of an RSA signature has an OID");
    AnySigner::new(
        RsaDigestSigner::new(
            RsaBlindedEngine::from_parts(RsaEngine::new(), UnwrapErr(SysRng)),
            digest::get(algorithm),
            AlgorithmIdentifier::with_null(oid.oid()),
        ),
        rsa_key,
        rsa_key,
    )
}

#[cfg(feature = "md2")]
pub(super) const MD2: SignerEntry = SignerEntry::new(
    &["MD2withRSA", "MD2withRSAEncryption"],
    &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02],
        "1.2.840.113549.1.1.2",
        "md2WithRSAEncryption",
    )],
    || signer(Algorithm::Md2),
);

// OIW 的兩個 OID 照 BC 也對到這一列
#[cfg(feature = "md4")]
pub(super) const MD4: SignerEntry = SignerEntry::new(
    &["MD4withRSA", "MD4withRSAEncryption"],
    &[
        NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x03],
            "1.2.840.113549.1.1.3",
            "md4WithRSAEncryption",
        ),
        NamedOid::new(
            &[0x2b, 0x0e, 0x03, 0x02, 0x02],
            "1.3.14.3.2.2",
            "md4WithRSA",
        ),
        NamedOid::new(
            &[0x2b, 0x0e, 0x03, 0x02, 0x04],
            "1.3.14.3.2.4",
            "oiw-md4WithRSAEncryption",
        ),
    ],
    || signer(Algorithm::Md4),
);

#[cfg(feature = "md5")]
pub(super) const MD5: SignerEntry = SignerEntry::new(
    &["MD5withRSA", "MD5withRSAEncryption"],
    &[
        NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04],
            "1.2.840.113549.1.1.4",
            "md5WithRSAEncryption",
        ),
        NamedOid::new(
            &[0x2b, 0x0e, 0x03, 0x02, 0x03],
            "1.3.14.3.2.3",
            "md5WithRSA",
        ),
    ],
    || signer(Algorithm::Md5),
);

#[cfg(feature = "sha1")]
pub(super) const SHA1: SignerEntry = SignerEntry::new(
    &[
        "SHA-1withRSA",
        "SHA1withRSA",
        "SHA1withRSAEncryption",
        "SHA-1withRSAEncryption",
    ],
    &[
        NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05],
            "1.2.840.113549.1.1.5",
            "sha1WithRSAEncryption",
        ),
        NamedOid::new(
            &[0x2b, 0x0e, 0x03, 0x02, 0x1d],
            "1.3.14.3.2.29",
            "sha1WithRSA",
        ),
    ],
    || signer(Algorithm::Sha1),
);

#[cfg(feature = "sha224")]
pub(super) const SHA224: SignerEntry = SignerEntry::new(
    &[
        "SHA-224withRSA",
        "SHA224withRSA",
        "SHA224withRSAEncryption",
        "SHA-224withRSAEncryption",
    ],
    &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e],
        "1.2.840.113549.1.1.14",
        "sha224WithRSAEncryption",
    )],
    || signer(Algorithm::Sha224),
);

#[cfg(feature = "sha256")]
pub(super) const SHA256: SignerEntry = SignerEntry::new(
    &[
        "SHA-256withRSA",
        "SHA256withRSA",
        "SHA256withRSAEncryption",
        "SHA-256withRSAEncryption",
    ],
    &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
        "1.2.840.113549.1.1.11",
        "sha256WithRSAEncryption",
    )],
    || signer(Algorithm::Sha256),
);

#[cfg(feature = "sha384")]
pub(super) const SHA384: SignerEntry = SignerEntry::new(
    &[
        "SHA-384withRSA",
        "SHA384withRSA",
        "SHA384withRSAEncryption",
        "SHA-384withRSAEncryption",
    ],
    &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c],
        "1.2.840.113549.1.1.12",
        "sha384WithRSAEncryption",
    )],
    || signer(Algorithm::Sha384),
);

#[cfg(feature = "sha512")]
pub(super) const SHA512: SignerEntry = SignerEntry::new(
    &[
        "SHA-512withRSA",
        "SHA512withRSA",
        "SHA512withRSAEncryption",
        "SHA-512withRSAEncryption",
    ],
    &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d],
        "1.2.840.113549.1.1.13",
        "sha512WithRSAEncryption",
    )],
    || signer(Algorithm::Sha512),
);

#[cfg(feature = "sha512-224")]
pub(super) const SHA512_224: SignerEntry = SignerEntry::new(
    &[
        "SHA-512(224)withRSA",
        "SHA512(224)withRSA",
        "SHA512(224)withRSAEncryption",
        "SHA-512(224)withRSAEncryption",
    ],
    &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0f],
        "1.2.840.113549.1.1.15",
        "sha512-224WithRSAEncryption",
    )],
    || signer(Algorithm::Sha512_224),
);

#[cfg(feature = "sha512-256")]
pub(super) const SHA512_256: SignerEntry = SignerEntry::new(
    &[
        "SHA-512(256)withRSA",
        "SHA512(256)withRSA",
        "SHA512(256)withRSAEncryption",
        "SHA-512(256)withRSAEncryption",
    ],
    &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x10],
        "1.2.840.113549.1.1.16",
        "sha512-256WithRSAEncryption",
    )],
    || signer(Algorithm::Sha512_256),
);

// NIST 的 id-rsassa-pkcs1-v1_5-with-sha3-*，BC 也對到這幾列
#[cfg(feature = "sha3-224")]
pub(super) const SHA3_224: SignerEntry = SignerEntry::new(
    &["SHA3-224withRSA", "SHA3-224withRSAEncryption"],
    &[NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0d],
        "2.16.840.1.101.3.4.3.13",
        "id-rsassa-pkcs1-v1_5-with-sha3-224",
    )],
    || signer(Algorithm::Sha3_224),
);
#[cfg(feature = "sha3-256")]
pub(super) const SHA3_256: SignerEntry = SignerEntry::new(
    &["SHA3-256withRSA", "SHA3-256withRSAEncryption"],
    &[NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0e],
        "2.16.840.1.101.3.4.3.14",
        "id-rsassa-pkcs1-v1_5-with-sha3-256",
    )],
    || signer(Algorithm::Sha3_256),
);

#[cfg(feature = "sha3-384")]
pub(super) const SHA3_384: SignerEntry = SignerEntry::new(
    &["SHA3-384withRSA", "SHA3-384withRSAEncryption"],
    &[NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0f],
        "2.16.840.1.101.3.4.3.15",
        "id-rsassa-pkcs1-v1_5-with-sha3-384",
    )],
    || signer(Algorithm::Sha3_384),
);

#[cfg(feature = "sha3-512")]
pub(super) const SHA3_512: SignerEntry = SignerEntry::new(
    &["SHA3-512withRSA", "SHA3-512withRSAEncryption"],
    &[NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10],
        "2.16.840.1.101.3.4.3.16",
        "id-rsassa-pkcs1-v1_5-with-sha3-512",
    )],
    || signer(Algorithm::Sha3_512),
);
