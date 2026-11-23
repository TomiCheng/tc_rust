use tc_asn1::Asn1Oid;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::DefaultAlgoAsn1Context;
use crate::mac::MacEntry;

pub(crate) type CreateRows = fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn MacEntry>>;

// What DefaultAlgoAsn1Builder starts with: the MACs of Bouncy Castle's DefaultMacAlgorithmFinder
pub(crate) const BUILT_IN: &[CreateRows] = &[hmac];

struct ByOid {
    name: &'static str,
    aliases: Vec<String>,
    algorithm: AlgorithmIdentifier,
    // The other OIDs read as this MAC
    also: Vec<Asn1Oid>,
}

impl MacEntry for ByOid {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn matches(&self, algorithm: &AlgorithmIdentifier) -> bool {
        self.algorithm.algorithm() == algorithm.algorithm()
            || self.also.contains(algorithm.algorithm())
    }
}

fn row(
    name: &'static str,
    alias: &str,
    algorithm: AlgorithmIdentifier,
    also: &[&str],
) -> Box<dyn MacEntry> {
    Box::new(ByOid {
        name,
        aliases: vec![alias.to_string()],
        algorithm,
        also: also.iter().map(|dotted| oid(dotted)).collect(),
    })
}

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().expect("the OIDs of the rows are valid")
}

// RFC 4231 writes HMAC with SHA-2 with a NULL; NIST CSOR the SHA-3 ones without. Bouncy Castle
// writes HMAC-SHA1 as the OID of SHA-1 itself, so hmacWithSHA1 of PKCS#5 and that of RFC 2104 are
// read as it too. The aliases are the names of Bouncy Castle's finder
fn hmac(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn MacEntry>> {
    vec![
        row(
            "HMAC-SHA1",
            "HMACSHA1",
            AlgorithmIdentifier::new(oid("1.3.14.3.2.26")),
            &["1.2.840.113549.2.7", "1.3.6.1.5.5.8.1.2"],
        ),
        row(
            "HMAC-SHA224",
            "HMACSHA224",
            AlgorithmIdentifier::with_null(oid("1.2.840.113549.2.8")),
            &[],
        ),
        row(
            "HMAC-SHA256",
            "HMACSHA256",
            AlgorithmIdentifier::with_null(oid("1.2.840.113549.2.9")),
            &[],
        ),
        row(
            "HMAC-SHA384",
            "HMACSHA384",
            AlgorithmIdentifier::with_null(oid("1.2.840.113549.2.10")),
            &[],
        ),
        row(
            "HMAC-SHA512",
            "HMACSHA512",
            AlgorithmIdentifier::with_null(oid("1.2.840.113549.2.11")),
            &[],
        ),
        row(
            "HMAC-SHA512-224",
            "HMACSHA512-224",
            AlgorithmIdentifier::with_null(oid("1.2.840.113549.2.12")),
            &[],
        ),
        row(
            "HMAC-SHA512-256",
            "HMACSHA512-256",
            AlgorithmIdentifier::with_null(oid("1.2.840.113549.2.13")),
            &[],
        ),
        row(
            "HMAC-SHA3-224",
            "HMACSHA3-224",
            AlgorithmIdentifier::new(oid("2.16.840.1.101.3.4.2.13")),
            &[],
        ),
        row(
            "HMAC-SHA3-256",
            "HMACSHA3-256",
            AlgorithmIdentifier::new(oid("2.16.840.1.101.3.4.2.14")),
            &[],
        ),
        row(
            "HMAC-SHA3-384",
            "HMACSHA3-384",
            AlgorithmIdentifier::new(oid("2.16.840.1.101.3.4.2.15")),
            &[],
        ),
        row(
            "HMAC-SHA3-512",
            "HMACSHA3-512",
            AlgorithmIdentifier::new(oid("2.16.840.1.101.3.4.2.16")),
            &[],
        ),
    ]
}
