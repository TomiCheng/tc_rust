use tc_asn1::{Asn1Oid, NamedOid};
use tc_asn1_pkcs::Pkcs12Algorithm;

// The PBE iteration count Bouncy Castle writes with; the MAC takes twice as many
const DEFAULT_ITERATIONS: usize = 300_000;

// How save encrypts, as Bouncy Castle's Pkcs12StoreBuilder sets it, with its defaults: the keys
// by PBEwithSHAAnd3-KeyTripleDES-CBC and the certificates by PBEwithSHAAnd40BitRC2-CBC. An
// algorithm is the OID of a PBE scheme, or with a PRF that of a cipher under PBES2, as AES-256-CBC
// with hmacWithSHA256
#[derive(Clone, Debug)]
pub struct Pkcs12Options {
    key_algorithm: Option<Asn1Oid>,
    key_prf: Option<Asn1Oid>,
    cert_algorithm: Option<Asn1Oid>,
    cert_prf: Option<Asn1Oid>,
    iterations: usize,
    oracle_trusted_key_usage: bool,
}

impl Default for Pkcs12Options {
    fn default() -> Self {
        Self {
            key_algorithm: Some(oid(Pkcs12Algorithm::PBE_WITH_SHA_AND_3_KEY_TRIPLE_DES_CBC)),
            key_prf: None,
            cert_algorithm: Some(oid(Pkcs12Algorithm::PBE_WITH_SHA_AND_40_BIT_RC2_CBC)),
            cert_prf: None,
            iterations: DEFAULT_ITERATIONS,
            oracle_trusted_key_usage: true,
        }
    }
}

fn oid(named: NamedOid) -> Asn1Oid {
    named.oid()
}

impl Pkcs12Options {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_key_algorithm(mut self, algorithm: Asn1Oid) -> Self {
        self.key_algorithm = Some(algorithm);
        self.key_prf = None;
        self
    }

    // PBES2 over the cipher, with the PRF for PBKDF2
    pub fn with_key_algorithm_and_prf(mut self, cipher: Asn1Oid, prf: Asn1Oid) -> Self {
        self.key_algorithm = Some(cipher);
        self.key_prf = Some(prf);
        self
    }

    // The keys go into keyBags, unencrypted
    pub fn without_key_encryption(mut self) -> Self {
        self.key_algorithm = None;
        self.key_prf = None;
        self
    }

    pub fn with_cert_algorithm(mut self, algorithm: Asn1Oid) -> Self {
        self.cert_algorithm = Some(algorithm);
        self.cert_prf = None;
        self
    }

    // PBES2 over the cipher, with the PRF for PBKDF2
    pub fn with_cert_algorithm_and_prf(mut self, cipher: Asn1Oid, prf: Asn1Oid) -> Self {
        self.cert_algorithm = Some(cipher);
        self.cert_prf = Some(prf);
        self
    }

    // The certificates go into data, unencrypted
    pub fn without_cert_encryption(mut self) -> Self {
        self.cert_algorithm = None;
        self.cert_prf = None;
        self
    }

    // The count of the PBE; a MAC not kept from a loaded file takes twice as many
    pub fn with_iterations(mut self, iterations: usize) -> Self {
        self.iterations = iterations;
        self
    }

    // The attribute of Oracle's (Java's) PKCS#12 that marks a certificate without a key as
    // trusted, on by default as in Bouncy Castle
    pub fn with_oracle_trusted_key_usage(mut self, enabled: bool) -> Self {
        self.oracle_trusted_key_usage = enabled;
        self
    }

    pub fn key_algorithm(&self) -> Option<&Asn1Oid> {
        self.key_algorithm.as_ref()
    }

    pub fn key_prf(&self) -> Option<&Asn1Oid> {
        self.key_prf.as_ref()
    }

    pub fn cert_algorithm(&self) -> Option<&Asn1Oid> {
        self.cert_algorithm.as_ref()
    }

    pub fn cert_prf(&self) -> Option<&Asn1Oid> {
        self.cert_prf.as_ref()
    }

    pub fn iterations(&self) -> usize {
        self.iterations
    }

    pub fn oracle_trusted_key_usage(&self) -> bool {
        self.oracle_trusted_key_usage
    }
}
