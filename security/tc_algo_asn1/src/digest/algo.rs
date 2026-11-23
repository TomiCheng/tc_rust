use tc_asn1::{Asn1Integer, Asn1Object, Asn1Oid};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::DefaultAlgoAsn1Context;
use crate::digest::DigestEntry;

pub(crate) type CreateRows = fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn DigestEntry>>;

// What DefaultAlgoAsn1Builder starts with: the digests of Bouncy Castle's
// DefaultDigestAlgorithmFinder, with its parameters and the signature algorithms hashing with each
pub(crate) const BUILT_IN: &[CreateRows] = &[sha, sha3, gost3411, md, ripemd, sm3];

struct ByOid {
    name: &'static str,
    aliases: Vec<String>,
    algorithm: AlgorithmIdentifier,
    signers: Vec<Asn1Oid>,
}

impl DigestEntry for ByOid {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn signers(&self) -> &[Asn1Oid] {
        &self.signers
    }
}

// A row written with the OID alone
fn bare(
    name: &'static str,
    aliases: &[&str],
    dotted: &str,
    signers: &[&str],
) -> Box<dyn DigestEntry> {
    boxed(
        name,
        aliases,
        AlgorithmIdentifier::new(oid(dotted)),
        signers,
    )
}

// A row written with a NULL, as the older digests are
fn null(
    name: &'static str,
    aliases: &[&str],
    dotted: &str,
    signers: &[&str],
) -> Box<dyn DigestEntry> {
    boxed(
        name,
        aliases,
        AlgorithmIdentifier::with_null(oid(dotted)),
        signers,
    )
}

fn boxed(
    name: &'static str,
    aliases: &[&str],
    algorithm: AlgorithmIdentifier,
    signers: &[&str],
) -> Box<dyn DigestEntry> {
    Box::new(ByOid {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        algorithm,
        signers: signers.iter().map(|dotted| oid(dotted)).collect(),
    })
}

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().expect("the OIDs of the rows are valid")
}

// RFC 3370 writes SHA-1 with a NULL; RFC 5754 the SHA-2 family without. The signature algorithms
// are those of PKCS#1, OIW, X9.57, X9.62, NIST, BSI (ecdsa-plain), BSI EAC and SM2
fn sha(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn DigestEntry>> {
    vec![
        null(
            "SHA-1",
            &["SHA1"],
            "1.3.14.3.2.26",
            &[
                "1.2.840.113549.1.1.5",
                "1.3.14.3.2.29",
                "1.2.840.10040.4.3",
                "1.3.14.3.2.27",
                "1.2.840.10045.4.1",
                "0.4.0.127.0.7.1.1.4.1.1",
                "0.4.0.127.0.7.2.2.2.2.1",
            ],
        ),
        bare(
            "SHA-224",
            &["SHA224"],
            "2.16.840.1.101.3.4.2.4",
            &[
                "1.2.840.113549.1.1.14",
                "2.16.840.1.101.3.4.3.1",
                "1.2.840.10045.4.3.1",
                "0.4.0.127.0.7.1.1.4.1.2",
                "0.4.0.127.0.7.2.2.2.2.2",
            ],
        ),
        bare(
            "SHA-256",
            &["SHA256"],
            "2.16.840.1.101.3.4.2.1",
            &[
                "1.2.840.113549.1.1.11",
                "2.16.840.1.101.3.4.3.2",
                "1.2.840.10045.4.3.2",
                "0.4.0.127.0.7.1.1.4.1.3",
                "0.4.0.127.0.7.2.2.2.2.3",
                "1.2.156.10197.1.503",
            ],
        ),
        bare(
            "SHA-384",
            &["SHA384"],
            "2.16.840.1.101.3.4.2.2",
            &[
                "1.2.840.113549.1.1.12",
                "2.16.840.1.101.3.4.3.3",
                "1.2.840.10045.4.3.3",
                "0.4.0.127.0.7.1.1.4.1.4",
                "0.4.0.127.0.7.2.2.2.2.4",
            ],
        ),
        // Ed25519 hashes with SHA-512, the digest RFC 8419 has CMS write for it
        bare(
            "SHA-512",
            &["SHA512"],
            "2.16.840.1.101.3.4.2.3",
            &[
                "1.2.840.113549.1.1.13",
                "2.16.840.1.101.3.4.3.4",
                "1.2.840.10045.4.3.4",
                "0.4.0.127.0.7.1.1.4.1.5",
                "0.4.0.127.0.7.2.2.2.2.5",
                "1.3.101.112",
            ],
        ),
        bare(
            "SHA-512/224",
            &[
                "SHA512/224",
                "SHA512-224",
                "SHA512(224)",
                "SHA-512-224",
                "SHA-512(224)",
            ],
            "2.16.840.1.101.3.4.2.5",
            &["1.2.840.113549.1.1.15"],
        ),
        bare(
            "SHA-512/256",
            &[
                "SHA512/256",
                "SHA512-256",
                "SHA512(256)",
                "SHA-512-256",
                "SHA-512(256)",
            ],
            "2.16.840.1.101.3.4.2.6",
            &["1.2.840.113549.1.1.16"],
        ),
    ]
}

// NIST CSOR. SHAKE as a digest has the output of RFC 8702: 32 bytes for SHAKE128, 64 for SHAKE256
fn sha3(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn DigestEntry>> {
    vec![
        bare(
            "SHA3-224",
            &[],
            "2.16.840.1.101.3.4.2.7",
            &[
                "2.16.840.1.101.3.4.3.5",
                "2.16.840.1.101.3.4.3.9",
                "2.16.840.1.101.3.4.3.13",
                "0.4.0.127.0.7.1.1.4.1.8",
            ],
        ),
        bare(
            "SHA3-256",
            &[],
            "2.16.840.1.101.3.4.2.8",
            &[
                "2.16.840.1.101.3.4.3.6",
                "2.16.840.1.101.3.4.3.10",
                "2.16.840.1.101.3.4.3.14",
                "0.4.0.127.0.7.1.1.4.1.9",
            ],
        ),
        bare(
            "SHA3-384",
            &[],
            "2.16.840.1.101.3.4.2.9",
            &[
                "2.16.840.1.101.3.4.3.7",
                "2.16.840.1.101.3.4.3.11",
                "2.16.840.1.101.3.4.3.15",
                "0.4.0.127.0.7.1.1.4.1.10",
            ],
        ),
        bare(
            "SHA3-512",
            &[],
            "2.16.840.1.101.3.4.2.10",
            &[
                "2.16.840.1.101.3.4.3.8",
                "2.16.840.1.101.3.4.3.12",
                "2.16.840.1.101.3.4.3.16",
                "0.4.0.127.0.7.1.1.4.1.11",
            ],
        ),
        // RFC 8692: RSASSA-PSS and ECDSA with SHAKE
        bare(
            "SHAKE128-256",
            &["SHAKE128", "SHAKE-128"],
            "2.16.840.1.101.3.4.2.11",
            &["1.3.6.1.5.5.7.6.30", "1.3.6.1.5.5.7.6.32"],
        ),
        bare(
            "SHAKE256-512",
            &["SHAKE256", "SHAKE-256"],
            "2.16.840.1.101.3.4.2.12",
            &["1.3.6.1.5.5.7.6.31", "1.3.6.1.5.5.7.6.33"],
        ),
        // RFC 8419: Ed448 is written with id-shake256-len of 512 bits. After the row above, so the
        // name finds that one
        Box::new(Shake256Len512 {
            algorithm: AlgorithmIdentifier::with_parameters(
                oid("2.16.840.1.101.3.4.2.18"),
                Asn1Object::Integer(Asn1Integer::from(512u64)),
            ),
            signers: vec![oid("1.3.101.113")],
        }),
    ]
}

// id-shake256-len with an output of 512 bits, the only length tc_algo has a row for
struct Shake256Len512 {
    algorithm: AlgorithmIdentifier,
    signers: Vec<Asn1Oid>,
}

impl DigestEntry for Shake256Len512 {
    fn name(&self) -> &str {
        "SHAKE256-512"
    }

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn matches(&self, algorithm: &AlgorithmIdentifier) -> bool {
        algorithm == &self.algorithm
    }

    fn signers(&self) -> &[Asn1Oid] {
        &self.signers
    }
}

// RFC 4357 writes GOST R 34.11-94 with a NULL; RFC 9215 the 2012 ones without
fn gost3411(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn DigestEntry>> {
    vec![
        null(
            "GOST3411",
            &[],
            "1.2.643.2.2.9",
            &["1.2.643.2.2.4", "1.2.643.2.2.3"],
        ),
        bare(
            "GOST3411-2012-256",
            &[],
            "1.2.643.7.1.1.2.2",
            &["1.2.643.7.1.1.3.2"],
        ),
        bare(
            "GOST3411-2012-512",
            &[],
            "1.2.643.7.1.1.2.3",
            &["1.2.643.7.1.1.3.3"],
        ),
    ]
}

// RFC 1319, 1320 and 1321
fn md(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn DigestEntry>> {
    vec![
        null("MD2", &[], "1.2.840.113549.2.2", &["1.2.840.113549.1.1.2"]),
        null(
            "MD4",
            &[],
            "1.2.840.113549.2.4",
            &["1.2.840.113549.1.1.3", "1.3.14.3.2.2", "1.3.14.3.2.4"],
        ),
        null(
            "MD5",
            &[],
            "1.2.840.113549.2.5",
            &["1.2.840.113549.1.1.4", "1.3.14.3.2.3"],
        ),
    ]
}

// No standard says how to write their parameters; Bouncy Castle keeps the NULL
fn ripemd(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn DigestEntry>> {
    vec![
        null(
            "RIPEMD128",
            &["RIPEMD-128"],
            "1.3.36.3.2.2",
            &["1.3.36.3.3.1.3"],
        ),
        null(
            "RIPEMD160",
            &["RIPEMD-160"],
            "1.3.36.3.2.1",
            &["1.3.36.3.3.1.2", "0.4.0.127.0.7.1.1.4.1.6"],
        ),
        null(
            "RIPEMD256",
            &["RIPEMD-256"],
            "1.3.36.3.2.3",
            &["1.3.36.3.3.1.4"],
        ),
    ]
}

// GM/T 0006, without parameters
fn sm3(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn DigestEntry>> {
    vec![bare(
        "SM3",
        &[],
        "1.2.156.10197.1.401",
        &["1.2.156.10197.1.501"],
    )]
}
