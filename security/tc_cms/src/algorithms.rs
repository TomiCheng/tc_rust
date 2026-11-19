use tc_asn1::{Asn1Object, Asn1Oid};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::CmsError;

const SHA1: &str = "1.3.14.3.2.26";
const SHA224: &str = "2.16.840.1.101.3.4.2.4";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const SHA384: &str = "2.16.840.1.101.3.4.2.2";
const SHA512: &str = "2.16.840.1.101.3.4.2.3";

// rsaEncryption，OpenSSL 在 SignerInfo 裡寫的簽章演算法
pub(crate) const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

// 簽章演算法對到的摘要，同 BC DefaultDigestAlgorithmFinder 的 DigestOids
const SIGNATURE_DIGESTS: &[(&str, &str)] = &[
    ("1.2.840.113549.1.1.5", SHA1),
    ("1.2.840.113549.1.1.14", SHA224),
    ("1.2.840.113549.1.1.11", SHA256),
    ("1.2.840.113549.1.1.12", SHA384),
    ("1.2.840.113549.1.1.13", SHA512),
    ("1.2.840.10045.4.1", SHA1),
    ("1.2.840.10045.4.3.1", SHA224),
    ("1.2.840.10045.4.3.2", SHA256),
    ("1.2.840.10045.4.3.3", SHA384),
    ("1.2.840.10045.4.3.4", SHA512),
];

// 摘要在 tc_x509 簽章名稱裡的寫法，如 SHA-256withRSA
const DIGEST_NAMES: &[(&str, &str)] = &[
    (SHA1, "SHA-1"),
    (SHA224, "SHA-224"),
    (SHA256, "SHA-256"),
    (SHA384, "SHA-384"),
    (SHA512, "SHA-512"),
];

// 簽章演算法的摘要識別碼：SHA-1 帶 NULL、SHA-2 不帶參數，同 BC
pub(crate) fn digest_of(signature: &AlgorithmIdentifier) -> Result<AlgorithmIdentifier, CmsError> {
    let dotted = signature.algorithm().to_string();
    let (_, digest) = SIGNATURE_DIGESTS
        .iter()
        .find(|(oid, _)| *oid == dotted)
        .ok_or(CmsError::UnknownAlgorithm)?;
    let oid: Asn1Oid = digest.parse()?;
    Ok(if *digest == SHA1 {
        AlgorithmIdentifier::with_null(oid)
    } else {
        AlgorithmIdentifier::new(oid)
    })
}

pub(crate) fn digest_name(digest: &Asn1Oid) -> Result<&'static str, CmsError> {
    let dotted = digest.to_string();
    DIGEST_NAMES
        .iter()
        .find(|(oid, _)| *oid == dotted)
        .map(|(_, name)| *name)
        .ok_or(CmsError::UnknownAlgorithm)
}

// 同 BC X509Utilities.AreEquivalentAlgorithms：OID 相同，參數相同或都是沒有／NULL
pub(crate) fn equivalent(a: &AlgorithmIdentifier, b: &AlgorithmIdentifier) -> bool {
    let absent =
        |id: &AlgorithmIdentifier| matches!(id.parameters(), None | Some(Asn1Object::Null(_)));
    a.algorithm() == b.algorithm() && ((absent(a) && absent(b)) || a.parameters() == b.parameters())
}

// id-RSAES-OAEP
pub(crate) const RSAES_OAEP: &str = "1.2.840.113549.1.1.7";

// 摘要在 tc_algo OAEP 名稱裡的寫法，如 RSA//OAEPWITHSHA256ANDMGF1PADDING
const OAEP_DIGESTS: &[(&str, &str)] = &[
    (SHA1, "SHA1"),
    (SHA224, "SHA224"),
    (SHA256, "SHA256"),
    (SHA384, "SHA384"),
    (SHA512, "SHA512"),
];

pub(crate) fn oaep_digest(digest: &Asn1Oid) -> Result<&'static str, CmsError> {
    let dotted = digest.to_string();
    OAEP_DIGESTS
        .iter()
        .find(|(oid, _)| *oid == dotted)
        .map(|(_, name)| *name)
        .ok_or(CmsError::UnknownAlgorithm)
}

// 內容加密演算法與金鑰長度，同 BC GeneratorUtilities.GetDefaultKeySize；參數是 IV
const CONTENT_CIPHERS: &[(&str, usize)] = &[
    ("2.16.840.1.101.3.4.1.2", 16),
    ("2.16.840.1.101.3.4.1.22", 24),
    ("2.16.840.1.101.3.4.1.42", 32),
    ("1.2.840.113549.3.7", 24),
];

pub(crate) fn content_key_length(cipher: &Asn1Oid) -> Result<usize, CmsError> {
    let dotted = cipher.to_string();
    CONTENT_CIPHERS
        .iter()
        .find(|(oid, _)| *oid == dotted)
        .map(|(_, length)| *length)
        .ok_or(CmsError::UnknownAlgorithm)
}
