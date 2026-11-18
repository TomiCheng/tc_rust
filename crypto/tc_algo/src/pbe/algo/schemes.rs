use std::mem;

use tc_asn1::Asn1Oid;
use tc_pbe::{
    OpenSslPbe, PbeError, PbeGenerator, PbeGeneratorInit, PbeParamsRef, Pkcs5S1, Pkcs12,
    pkcs5_password_to_bytes, pkcs12_password_to_bytes,
};
use tc_zeroize::Zeroizing;

use crate::params::{cipher::KeyWithIvOwned, key::KeyOwned};
use crate::pbe::{Pbe, PbeEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

type Generator = Box<dyn PbeGenerator<Error = PbeError>>;

// A generator of the scheme over one digest, initialized with the params
type MakeGenerator = fn(Scheme, &PbeParamsRef<'_>) -> Result<Generator, PbeError>;

// The rows of Bouncy Castle's PbeUtilities whose params it can generate, to give to
// DefaultAlgoBuilder::reg_pbe: PKCS#5 v1, PKCS#12 and OpenSSL schemes for a cipher, and the PKCS#12
// schemes for HMAC. Each row exists when the pbe feature and those of its digest and its cipher or
// HMAC are on. The names, aliases and OIDs are Bouncy Castle's; the OID of a PBEwithHmac row is that
// of its digest, as there. The lengths are those of GenerateCipherParameters, and the keys of DES
// and DESede get odd parity, as FixDesParity gives them. PBEwithSHA-1andIDEA-CBC and
// PBEwithSHA-1andTWOFISH-CBC are left out: Bouncy Castle names them but generates no params for them
pub(super) fn schemes(_context: &DefaultAlgoContext) -> Vec<Box<dyn PbeEntry>> {
    #[allow(unused_mut, reason = "empty when no digest and cipher are on")]
    let mut rows: Vec<Box<dyn PbeEntry>> = Vec::new();

    // PKCS#5 v1, of RFC 8018
    #[cfg(all(feature = "md", feature = "des"))]
    rows.push(cipher(
        "PBEwithMD2andDES-CBC",
        &[],
        &["1.2.840.113549.1.5.1"],
        Scheme::Pkcs5S1,
        md2,
        Target::Des,
        8,
    ));
    #[cfg(all(feature = "md", feature = "rc-cipher"))]
    rows.push(cipher(
        "PBEwithMD2andRC2-CBC",
        &[],
        &["1.2.840.113549.1.5.4"],
        Scheme::Pkcs5S1,
        md2,
        Target::Rc2,
        8,
    ));
    #[cfg(all(feature = "md", feature = "des"))]
    rows.push(cipher(
        "PBEwithMD5andDES-CBC",
        &[],
        &["1.2.840.113549.1.5.3"],
        Scheme::Pkcs5S1,
        md5,
        Target::Des,
        8,
    ));
    #[cfg(all(feature = "md", feature = "rc-cipher"))]
    rows.push(cipher(
        "PBEwithMD5andRC2-CBC",
        &[],
        &["1.2.840.113549.1.5.6"],
        Scheme::Pkcs5S1,
        md5,
        Target::Rc2,
        8,
    ));
    #[cfg(all(feature = "sha", feature = "des"))]
    rows.push(cipher(
        "PBEwithSHA-1andDES-CBC",
        &[
            "PBEWITHSHA1ANDDES",
            "PBEWITHSHA-1ANDDES",
            "PBEWITHSHA1ANDDES-CBC",
        ],
        &["1.2.840.113549.1.5.10"],
        Scheme::Pkcs5S1,
        sha1,
        Target::Des,
        8,
    ));
    #[cfg(all(feature = "sha", feature = "rc-cipher"))]
    rows.push(cipher(
        "PBEwithSHA-1andRC2-CBC",
        &[
            "PBEWITHSHA1ANDRC2",
            "PBEWITHSHA-1ANDRC2",
            "PBEWITHSHA1ANDRC2-CBC",
        ],
        &["1.2.840.113549.1.5.11"],
        Scheme::Pkcs5S1,
        sha1,
        Target::Rc2,
        8,
    ));

    // PKCS#12, of RFC 7292, over SHA-1
    #[cfg(all(feature = "sha", feature = "rc4-family"))]
    rows.push(cipher(
        "PBEwithSHA-1and128bitRC4",
        &["PBEWITHSHAAND128BITRC4", "PBEWITHSHA1AND128BITRC4"],
        &["1.2.840.113549.1.12.1.1"],
        Scheme::Pkcs12,
        sha1,
        Target::Rc4,
        16,
    ));
    #[cfg(all(feature = "sha", feature = "rc4-family"))]
    rows.push(cipher(
        "PBEwithSHA-1and40bitRC4",
        &["PBEWITHSHAAND40BITRC4", "PBEWITHSHA1AND40BITRC4"],
        &["1.2.840.113549.1.12.1.2"],
        Scheme::Pkcs12,
        sha1,
        Target::Rc4,
        5,
    ));
    #[cfg(all(feature = "sha", feature = "des"))]
    rows.push(cipher(
        "PBEwithSHA-1and3-keyDESEDE-CBC",
        &[
            "PBEWITHSHAAND3-KEYDESEDE-CBC",
            "PBEWITHSHAAND3-KEYTRIPLEDES-CBC",
            "PBEWITHSHA1AND3-KEYDESEDE-CBC",
            "PBEWITHSHA1AND3-KEYTRIPLEDES-CBC",
            "PBEWITHSHA-1AND3-KEYTRIPLEDES-CBC",
        ],
        &["1.2.840.113549.1.12.1.3"],
        Scheme::Pkcs12,
        sha1,
        Target::DesEde,
        24,
    ));
    #[cfg(all(feature = "sha", feature = "des"))]
    rows.push(cipher(
        "PBEwithSHA-1and2-keyDESEDE-CBC",
        &[
            "PBEWITHSHAAND2-KEYDESEDE-CBC",
            "PBEWITHSHAAND2-KEYTRIPLEDES-CBC",
            "PBEWITHSHA1AND2-KEYDESEDE-CBC",
            "PBEWITHSHA1AND2-KEYTRIPLEDES-CBC",
            "PBEWITHSHA-1AND2-KEYTRIPLEDES-CBC",
        ],
        &["1.2.840.113549.1.12.1.4"],
        Scheme::Pkcs12,
        sha1,
        Target::DesEde,
        16,
    ));
    #[cfg(all(feature = "sha", feature = "rc-cipher"))]
    rows.push(cipher(
        "PBEwithSHA-1and128bitRC2-CBC",
        &["PBEWITHSHAAND128BITRC2-CBC", "PBEWITHSHA1AND128BITRC2-CBC"],
        &["1.2.840.113549.1.12.1.5"],
        Scheme::Pkcs12,
        sha1,
        Target::Rc2,
        16,
    ));
    #[cfg(all(feature = "sha", feature = "rc-cipher"))]
    rows.push(cipher(
        "PBEwithSHA-1and40bitRC2-CBC",
        &["PBEWITHSHAAND40BITRC2-CBC", "PBEWITHSHA1AND40BITRC2-CBC"],
        &["1.2.840.113549.1.12.1.6"],
        Scheme::Pkcs12,
        sha1,
        Target::Rc2,
        5,
    ));
    #[cfg(all(feature = "sha", feature = "aes"))]
    rows.push(cipher(
        "PBEwithSHA-1and128bitAES-CBC-BC",
        &[
            "PBEWITHSHAAND128BITAES-CBC-BC",
            "PBEWITHSHA1AND128BITAES-CBC-BC",
        ],
        &["1.3.6.1.4.1.22554.1.1.2.1.2"],
        Scheme::Pkcs12,
        sha1,
        Target::Aes,
        16,
    ));
    #[cfg(all(feature = "sha", feature = "aes"))]
    rows.push(cipher(
        "PBEwithSHA-1and192bitAES-CBC-BC",
        &[
            "PBEWITHSHAAND192BITAES-CBC-BC",
            "PBEWITHSHA1AND192BITAES-CBC-BC",
        ],
        &["1.3.6.1.4.1.22554.1.1.2.1.22"],
        Scheme::Pkcs12,
        sha1,
        Target::Aes,
        24,
    ));
    #[cfg(all(feature = "sha", feature = "aes"))]
    rows.push(cipher(
        "PBEwithSHA-1and256bitAES-CBC-BC",
        &[
            "PBEWITHSHAAND256BITAES-CBC-BC",
            "PBEWITHSHA1AND256BITAES-CBC-BC",
        ],
        &["1.3.6.1.4.1.22554.1.1.2.1.42"],
        Scheme::Pkcs12,
        sha1,
        Target::Aes,
        32,
    ));

    // PKCS#12 over SHA-256
    #[cfg(all(feature = "sha", feature = "aes"))]
    rows.push(cipher(
        "PBEwithSHA-256and128bitAES-CBC-BC",
        &["PBEWITHSHA256AND128BITAES-CBC-BC"],
        &["1.3.6.1.4.1.22554.1.2.1.2.1.2"],
        Scheme::Pkcs12,
        sha256,
        Target::Aes,
        16,
    ));
    #[cfg(all(feature = "sha", feature = "aes"))]
    rows.push(cipher(
        "PBEwithSHA-256and192bitAES-CBC-BC",
        &["PBEWITHSHA256AND192BITAES-CBC-BC"],
        &["1.3.6.1.4.1.22554.1.2.1.2.1.22"],
        Scheme::Pkcs12,
        sha256,
        Target::Aes,
        24,
    ));
    #[cfg(all(feature = "sha", feature = "aes"))]
    rows.push(cipher(
        "PBEwithSHA-256and256bitAES-CBC-BC",
        &["PBEWITHSHA256AND256BITAES-CBC-BC"],
        &["1.3.6.1.4.1.22554.1.2.1.2.1.42"],
        Scheme::Pkcs12,
        sha256,
        Target::Aes,
        32,
    ));

    // OpenSSL's EVP_BytesToKey over MD5
    #[cfg(all(feature = "md", feature = "aes"))]
    rows.push(cipher(
        "PBEwithMD5and128bitAES-CBC-OpenSSL",
        &[],
        &[],
        Scheme::OpenSsl,
        md5,
        Target::Aes,
        16,
    ));
    #[cfg(all(feature = "md", feature = "aes"))]
    rows.push(cipher(
        "PBEwithMD5and192bitAES-CBC-OpenSSL",
        &[],
        &[],
        Scheme::OpenSsl,
        md5,
        Target::Aes,
        24,
    ));
    #[cfg(all(feature = "md", feature = "aes"))]
    rows.push(cipher(
        "PBEwithMD5and256bitAES-CBC-OpenSSL",
        &[],
        &[],
        Scheme::OpenSsl,
        md5,
        Target::Aes,
        32,
    ));

    // PKCS#12 keys for HMAC, as long as the digest
    #[cfg(all(feature = "macs", feature = "sha"))]
    rows.push(mac(
        "PBEwithHmacSHA-1",
        &["PBEWITHHMACSHA1"],
        &["1.3.14.3.2.26"],
        sha1,
        "HMAC-SHA1",
        20,
    ));
    #[cfg(all(feature = "macs", feature = "sha"))]
    rows.push(mac(
        "PBEwithHmacSHA-224",
        &["PBEWITHHMACSHA224"],
        &["2.16.840.1.101.3.4.2.4"],
        sha224,
        "HMAC-SHA224",
        28,
    ));
    #[cfg(all(feature = "macs", feature = "sha"))]
    rows.push(mac(
        "PBEwithHmacSHA-256",
        &["PBEWITHHMACSHA256"],
        &["2.16.840.1.101.3.4.2.1"],
        sha256,
        "HMAC-SHA256",
        32,
    ));
    #[cfg(all(feature = "macs", feature = "sha"))]
    rows.push(mac(
        "PBEwithHmacSHA-384",
        &["PBEWITHHMACSHA384"],
        &["2.16.840.1.101.3.4.2.2"],
        sha384,
        "HMAC-SHA384",
        48,
    ));
    #[cfg(all(feature = "macs", feature = "sha"))]
    rows.push(mac(
        "PBEwithHmacSHA-512",
        &["PBEWITHHMACSHA512"],
        &["2.16.840.1.101.3.4.2.3"],
        sha512,
        "HMAC-SHA512",
        64,
    ));
    #[cfg(all(feature = "macs", feature = "ripemd"))]
    rows.push(mac(
        "PBEwithHmacRipeMD128",
        &[],
        &["1.3.36.3.2.2"],
        ripemd128,
        "HMAC-RIPEMD128",
        16,
    ));
    #[cfg(all(feature = "macs", feature = "ripemd"))]
    rows.push(mac(
        "PBEwithHmacRipeMD160",
        &[],
        &["1.3.36.3.2.1"],
        ripemd160,
        "HMAC-RIPEMD160",
        20,
    ));
    #[cfg(all(feature = "macs", feature = "ripemd"))]
    rows.push(mac(
        "PBEwithHmacRipeMD256",
        &[],
        &["1.3.36.3.2.3"],
        ripemd256,
        "HMAC-RIPEMD256",
        32,
    ));
    #[cfg(all(feature = "macs", feature = "misc-digest"))]
    rows.push(mac("PBEwithHmacTiger", &[], &[], tiger, "HMAC-TIGER", 24));

    rows
}

// The generator a scheme derives with, and how it turns the password into bytes
#[allow(
    dead_code,
    reason = "a scheme whose digests and ciphers are off has no row"
)]
#[derive(Clone, Copy)]
enum Scheme {
    Pkcs5S1,
    Pkcs12,
    OpenSsl,
}

// The cipher row the params go to, with the length of its IV
#[allow(dead_code, reason = "a cipher whose feature is off has no row")]
#[derive(Clone, Copy)]
enum Target {
    Aes,
    Des,
    DesEde,
    Rc2,
    Rc4,
}

impl Target {
    fn name(self) -> &'static str {
        match self {
            Self::Aes => "AES/CBC/PKCS7PADDING",
            Self::Des => "DES/CBC/PKCS7PADDING",
            Self::DesEde => "DESEDE/CBC/PKCS7PADDING",
            Self::Rc2 => "RC2/CBC/PKCS7PADDING",
            Self::Rc4 => "ARC4",
        }
    }

    fn iv_bytes(self) -> usize {
        match self {
            Self::Aes => 16,
            Self::Des | Self::DesEde | Self::Rc2 => 8,
            Self::Rc4 => 0,
        }
    }
}

#[derive(Clone, Copy)]
enum Purpose {
    Cipher {
        target: Target,
        key_bytes: usize,
    },
    Mac {
        target: &'static str,
        key_bytes: usize,
    },
}

#[allow(dead_code, reason = "unused when no cipher is on")]
fn cipher(
    name: &'static str,
    aliases: &[&str],
    oids: &[&str],
    scheme: Scheme,
    make: MakeGenerator,
    target: Target,
    key_bytes: usize,
) -> Box<dyn PbeEntry> {
    row(
        name,
        aliases,
        oids,
        scheme,
        make,
        Purpose::Cipher { target, key_bytes },
    )
}

#[allow(dead_code, reason = "unused when hmac is off")]
fn mac(
    name: &'static str,
    aliases: &[&str],
    oids: &[&str],
    make: MakeGenerator,
    target: &'static str,
    key_bytes: usize,
) -> Box<dyn PbeEntry> {
    row(
        name,
        aliases,
        oids,
        Scheme::Pkcs12,
        make,
        Purpose::Mac { target, key_bytes },
    )
}

#[allow(dead_code, reason = "unused when no row is on")]
fn row(
    name: &'static str,
    aliases: &[&str],
    oids: &[&str],
    scheme: Scheme,
    make: MakeGenerator,
    purpose: Purpose,
) -> Box<dyn PbeEntry> {
    Box::new(Row {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        oids: oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect(),
        derivation: Derivation {
            scheme,
            make,
            purpose,
        },
    })
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    derivation: Derivation,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl PbeEntry for Row {
    fn create(&self) -> Box<dyn Pbe> {
        Box::new(self.derivation)
    }
}

// What a row derives: the scheme, its generator over the row's digest, and what the params are for
#[derive(Clone, Copy)]
struct Derivation {
    scheme: Scheme,
    make: MakeGenerator,
    purpose: Purpose,
}

impl Pbe for Derivation {
    fn target(&self) -> &str {
        match self.purpose {
            Purpose::Cipher { target, .. } => target.name(),
            Purpose::Mac { target, .. } => target,
        }
    }

    fn generate_params(
        &self,
        password: &str,
        salt: &[u8],
        iterations: usize,
    ) -> Result<Box<dyn Params>, AlgoError> {
        let invalid = |error| AlgoError::with_source(ErrorKind::InvalidParams, error);
        let Self {
            scheme,
            make,
            purpose,
        } = *self;
        let password = match scheme {
            Scheme::Pkcs12 => pkcs12_password_to_bytes(password, false),
            Scheme::Pkcs5S1 | Scheme::OpenSsl => pkcs5_password_to_bytes(password),
        };
        let mut generator =
            make(scheme, &PbeParamsRef::new(&password, salt, iterations)).map_err(invalid)?;

        match purpose {
            Purpose::Cipher { target, key_bytes } => {
                let mut key = Zeroizing::new(vec![0; key_bytes]);
                let mut iv = vec![0; target.iv_bytes()];
                generator
                    .derive_key_and_iv(&mut key, &mut iv)
                    .map_err(invalid)?;
                #[cfg(feature = "des")]
                if matches!(target, Target::Des | Target::DesEde) {
                    tc_des::set_odd_parity(&mut key);
                }
                let key = mem::take(&mut *key);
                Ok(if iv.is_empty() {
                    Box::new(KeyOwned::new(key))
                } else {
                    Box::new(KeyWithIvOwned::new(key, iv))
                })
            }
            Purpose::Mac { key_bytes, .. } => {
                let mut key = Zeroizing::new(vec![0; key_bytes]);
                generator.derive_mac_key(&mut key).map_err(invalid)?;
                Ok(Box::new(KeyOwned::new(mem::take(&mut *key))))
            }
        }
    }
}

// The generator of `scheme` over `digest`, initialized with `params`
#[allow(dead_code, reason = "unused when no row is on")]
fn generator<D: tc_digest::Digest + 'static>(
    scheme: Scheme,
    digest: D,
    params: &PbeParamsRef<'_>,
) -> Result<Generator, PbeError> {
    match scheme {
        Scheme::Pkcs5S1 => initialized(Pkcs5S1::new(digest), params),
        Scheme::Pkcs12 => initialized(Pkcs12::new(digest), params),
        Scheme::OpenSsl => initialized(OpenSslPbe::new(digest), params),
    }
}

#[allow(dead_code, reason = "unused when no row is on")]
fn initialized<G>(mut generator: G, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError>
where
    G: PbeGenerator<Error = PbeError>
        + for<'a> PbeGeneratorInit<PbeParamsRef<'a>, Error = PbeError>
        + 'static,
{
    generator.init(params)?;
    Ok(Box::new(generator))
}

#[cfg(feature = "md")]
#[allow(dead_code, reason = "unused when no cipher of it is on")]
fn md2(scheme: Scheme, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError> {
    generator(scheme, tc_md::Md2Digest::new(), params)
}

#[cfg(feature = "md")]
#[allow(dead_code, reason = "unused when no cipher of it is on")]
fn md5(scheme: Scheme, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError> {
    generator(scheme, tc_md::Md5Digest::new(), params)
}

#[cfg(feature = "sha")]
#[allow(dead_code, reason = "unused when no cipher of it is on")]
fn sha1(scheme: Scheme, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError> {
    generator(scheme, tc_sha::Sha1Digest::new(), params)
}

#[cfg(feature = "sha")]
#[allow(dead_code, reason = "unused when hmac is off")]
fn sha224(scheme: Scheme, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError> {
    generator(scheme, tc_sha::Sha224Digest::new(), params)
}

#[cfg(feature = "sha")]
#[allow(dead_code, reason = "unused when no cipher of it is on")]
fn sha256(scheme: Scheme, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError> {
    generator(scheme, tc_sha::Sha256Digest::new(), params)
}

#[cfg(feature = "sha")]
#[allow(dead_code, reason = "unused when hmac is off")]
fn sha384(scheme: Scheme, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError> {
    generator(scheme, tc_sha::Sha384Digest::new(), params)
}

#[cfg(feature = "sha")]
#[allow(dead_code, reason = "unused when hmac is off")]
fn sha512(scheme: Scheme, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError> {
    generator(scheme, tc_sha::Sha512Digest::new(), params)
}

#[cfg(feature = "ripemd")]
#[allow(dead_code, reason = "unused when hmac is off")]
fn ripemd128(scheme: Scheme, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError> {
    generator(scheme, tc_ripemd::RipeMd128Digest::default(), params)
}

#[cfg(feature = "ripemd")]
#[allow(dead_code, reason = "unused when hmac is off")]
fn ripemd160(scheme: Scheme, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError> {
    generator(scheme, tc_ripemd::RipeMd160Digest::default(), params)
}

#[cfg(feature = "ripemd")]
#[allow(dead_code, reason = "unused when hmac is off")]
fn ripemd256(scheme: Scheme, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError> {
    generator(scheme, tc_ripemd::RipeMd256Digest::default(), params)
}

#[cfg(feature = "misc-digest")]
#[allow(dead_code, reason = "unused when hmac is off")]
fn tiger(scheme: Scheme, params: &PbeParamsRef<'_>) -> Result<Generator, PbeError> {
    generator(scheme, tc_misc_digest::TigerDigest::default(), params)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports, reason = "each test uses some")]
    use crate::params::{cipher::IvParams, cipher::KeyWithIvOwned, key::KeyOwned, key::KeyParams};
    #[allow(unused_imports, reason = "each test uses some")]
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    #[allow(dead_code, reason = "unused when no row is on")]
    const SALT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    #[allow(dead_code, reason = "unused when no row is on")]
    const ITERATIONS: usize = 2048;

    #[cfg(all(feature = "sha", feature = "aes"))]
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    #[cfg(all(feature = "sha", feature = "aes"))]
    #[test]
    fn the_sha_256_aes_rows_derive_the_expected_key_and_iv_by_name_and_oid() {
        // RFC 7292 has no vectors for SHA-256, so these come from its appendix B written out in
        // Python
        const IV: &str = "30938f79be0bc0f698680e658c91b5ee";
        const ROWS: [(&str, &str, &str); 3] = [
            (
                "PBEwithSHA-256and128bitAES-CBC-BC",
                "1.3.6.1.4.1.22554.1.2.1.2.1.2",
                "d8fb52dd9042c1031f9a18e5957a3be6",
            ),
            (
                "PBEwithSHA-256and192bitAES-CBC-BC",
                "1.3.6.1.4.1.22554.1.2.1.2.1.22",
                "d8fb52dd9042c1031f9a18e5957a3be69ead00cf867836e8",
            ),
            (
                "PBEwithSHA-256and256bitAES-CBC-BC",
                "1.3.6.1.4.1.22554.1.2.1.2.1.42",
                "d8fb52dd9042c1031f9a18e5957a3be69ead00cf867836e84f3363150bd5657a",
            ),
        ];
        let algo = DefaultAlgoBuilder::default().build();
        for (name, dotted, key) in ROWS {
            let by_oid = algo.pbe().get_by_oid(&dotted.parse().unwrap()).unwrap();
            for pbe in [algo.pbe().get_by_name(name).unwrap(), by_oid] {
                let params = pbe.generate_params("password", &SALT, ITERATIONS).unwrap();
                let params = params.as_any().downcast_ref::<KeyWithIvOwned>().unwrap();
                assert_eq!(params.key(), hex(key), "{name}");
                assert_eq!(params.iv(), hex(IV), "{name}");
            }
        }
    }

    // Every row Bouncy Castle can generate params for, with its OID if it has one, and an alias
    #[cfg(all(
        feature = "md",
        feature = "sha",
        feature = "ripemd",
        feature = "misc-digest",
        feature = "des",
        feature = "rc-cipher",
        feature = "rc4-family",
        feature = "aes",
        feature = "macs"
    ))]
    #[test]
    fn every_row_finds_by_name_and_oid_and_its_params_work_on_its_target() {
        const ALL: [(&str, Option<&str>); 31] = [
            ("PBEwithMD2andDES-CBC", Some("1.2.840.113549.1.5.1")),
            ("PBEwithMD2andRC2-CBC", Some("1.2.840.113549.1.5.4")),
            ("PBEwithMD5andDES-CBC", Some("1.2.840.113549.1.5.3")),
            ("PBEwithMD5andRC2-CBC", Some("1.2.840.113549.1.5.6")),
            ("PBEwithSHA-1andDES-CBC", Some("1.2.840.113549.1.5.10")),
            ("PBEwithSHA-1andRC2-CBC", Some("1.2.840.113549.1.5.11")),
            ("PBEwithSHA-1and128bitRC4", Some("1.2.840.113549.1.12.1.1")),
            ("PBEwithSHA-1and40bitRC4", Some("1.2.840.113549.1.12.1.2")),
            (
                "PBEwithSHA-1and3-keyDESEDE-CBC",
                Some("1.2.840.113549.1.12.1.3"),
            ),
            (
                "PBEwithSHA-1and2-keyDESEDE-CBC",
                Some("1.2.840.113549.1.12.1.4"),
            ),
            (
                "PBEwithSHA-1and128bitRC2-CBC",
                Some("1.2.840.113549.1.12.1.5"),
            ),
            (
                "PBEwithSHA-1and40bitRC2-CBC",
                Some("1.2.840.113549.1.12.1.6"),
            ),
            (
                "PBEwithSHA-1and128bitAES-CBC-BC",
                Some("1.3.6.1.4.1.22554.1.1.2.1.2"),
            ),
            (
                "PBEwithSHA-1and192bitAES-CBC-BC",
                Some("1.3.6.1.4.1.22554.1.1.2.1.22"),
            ),
            (
                "PBEwithSHA-1and256bitAES-CBC-BC",
                Some("1.3.6.1.4.1.22554.1.1.2.1.42"),
            ),
            (
                "PBEwithSHA-256and128bitAES-CBC-BC",
                Some("1.3.6.1.4.1.22554.1.2.1.2.1.2"),
            ),
            (
                "PBEwithSHA-256and192bitAES-CBC-BC",
                Some("1.3.6.1.4.1.22554.1.2.1.2.1.22"),
            ),
            (
                "PBEwithSHA-256and256bitAES-CBC-BC",
                Some("1.3.6.1.4.1.22554.1.2.1.2.1.42"),
            ),
            ("PBEwithMD5and128bitAES-CBC-OpenSSL", None),
            ("PBEwithMD5and192bitAES-CBC-OpenSSL", None),
            ("PBEwithMD5and256bitAES-CBC-OpenSSL", None),
            ("PBEwithHmacSHA-1", Some("1.3.14.3.2.26")),
            ("PBEwithHmacSHA-224", Some("2.16.840.1.101.3.4.2.4")),
            ("PBEwithHmacSHA-256", Some("2.16.840.1.101.3.4.2.1")),
            ("PBEwithHmacSHA-384", Some("2.16.840.1.101.3.4.2.2")),
            ("PBEwithHmacSHA-512", Some("2.16.840.1.101.3.4.2.3")),
            ("PBEwithHmacRipeMD128", Some("1.3.36.3.2.2")),
            ("PBEwithHmacRipeMD160", Some("1.3.36.3.2.1")),
            ("PBEwithHmacRipeMD256", Some("1.3.36.3.2.3")),
            ("PBEwithHmacTiger", None),
            ("PBEWITHSHAAND3-KEYTRIPLEDES-CBC", None),
        ];
        let algo = DefaultAlgoBuilder::default().build();
        let message = b"attack at dawn";
        for (name, dotted) in ALL {
            let mut found = vec![algo.pbe().get_by_name(name).unwrap()];
            if let Some(dotted) = dotted {
                found.push(algo.pbe().get_by_oid(&dotted.parse().unwrap()).unwrap());
            }
            for pbe in found {
                let params = pbe.generate_params("password", &SALT, ITERATIONS).unwrap();
                let target = pbe.target();
                if target.starts_with("HMAC-") {
                    let mut mac = algo.mac().get_by_name(target).unwrap();
                    mac.init(params.as_ref()).unwrap();
                    mac.update(message).unwrap();
                    assert_eq!(mac.finalize().unwrap().len(), mac.mac_size(), "{name}");
                    continue;
                }
                let sealed = algo
                    .cipher()
                    .encrypt_by_name(target, params.as_ref(), message)
                    .unwrap();
                let opened = algo
                    .cipher()
                    .decrypt_by_name(target, params.as_ref(), &sealed)
                    .unwrap();
                assert_eq!(opened, message, "{name}");
            }
        }
    }

    #[cfg(all(feature = "md", feature = "des", feature = "sha"))]
    #[test]
    fn des_and_desede_keys_get_odd_parity() {
        let algo = DefaultAlgoBuilder::default().build();
        for name in ["PBEwithMD5andDES-CBC", "PBEwithSHA-1and3-keyDESEDE-CBC"] {
            let pbe = algo.pbe().get_by_name(name).unwrap();
            let params = pbe.generate_params("password", &SALT, ITERATIONS).unwrap();
            let params = params.as_any().downcast_ref::<KeyWithIvOwned>().unwrap();
            assert!(
                params.key().iter().all(|byte| byte.count_ones() % 2 == 1),
                "{name}"
            );
            assert_eq!(params.iv().len(), 8, "{name}");
        }
    }

    #[cfg(all(feature = "sha", feature = "rc4-family", feature = "macs"))]
    #[test]
    fn rc4_takes_a_key_alone_and_hmac_a_key_as_long_as_the_digest() {
        let algo = DefaultAlgoBuilder::default().build();
        for (name, length) in [("PBEwithSHA-1and40bitRC4", 5), ("PBEwithHmacSHA-512", 64)] {
            let pbe = algo.pbe().get_by_name(name).unwrap();
            let params = pbe.generate_params("password", &SALT, ITERATIONS).unwrap();
            let key = params.as_any().downcast_ref::<KeyOwned>().unwrap();
            assert_eq!(key.key().len(), length, "{name}");
        }
    }

    #[cfg(all(feature = "sha", feature = "aes"))]
    #[test]
    fn another_password_or_salt_derives_another_key_and_a_count_of_0_is_refused() {
        let algo = DefaultAlgoBuilder::default().build();
        let pbe = algo
            .pbe()
            .get_by_name("pbewithsha256and128bitaes-cbc-bc")
            .unwrap();
        let key = |password: &str, salt: &[u8]| {
            let params = pbe.generate_params(password, salt, ITERATIONS).unwrap();
            let params = params.as_any().downcast_ref::<KeyWithIvOwned>().unwrap();
            params.key().to_vec()
        };
        assert_ne!(key("password", &SALT), key("passwore", &SALT));
        assert_ne!(key("password", &SALT), key("password", &[9; 8]));

        let error = pbe.generate_params("password", &SALT, 0).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
