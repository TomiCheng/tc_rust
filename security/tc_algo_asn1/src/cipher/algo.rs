use rand_core::CryptoRng;
use tc_algo::Params;
use tc_algo::params::cipher::{AeadParamsOwned, KeyWithIvOwned};
use tc_algo::params::key::{KeyOwned, KeyParams};
use tc_asn1::{Asn1Object, Asn1OctetString, Asn1Oid, Decode, Encode, EncodingOptions};
use tc_asn1_cms::params::{CcmParameters, GcmParameters};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::cipher::CipherEntry;
use crate::der::decode_all;
use crate::{AlgoAsn1Error, DefaultAlgoAsn1Context};

pub(crate) type CreateRows = fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn CipherEntry>>;

// What DefaultAlgoAsn1Builder starts with: the content ciphers of CMS, whose parameters are those
// of Bouncy Castle's ParameterUtilities for the CBC ones and those of RFC 5084 and RFC 8103 for
// the AEAD ones
pub(crate) const BUILT_IN: &[CreateRows] =
    &[aes, des, camellia, seed, aria, sm4, chacha20_poly1305];

// How the parameters are written
#[derive(Clone, Copy)]
enum Kind {
    // The IV as an OCTET STRING, as CBC has it
    Iv(usize),
    // GCMParameters of RFC 5084: a nonce of 12 bytes and a tag of 16
    Gcm,
    // CCMParameters of RFC 5084: a nonce of 12 bytes and a tag of 16
    Ccm,
    // RFC 8103: the nonce of 12 bytes as an OCTET STRING, with a tag of 16
    ChaCha20Poly1305,
}

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

struct Row {
    name: &'static str,
    cipher: &'static str,
    oid: Asn1Oid,
    key_size: usize,
    kind: Kind,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl Row {
    fn random(&self, size: usize) -> Vec<u8> {
        let mut bytes = vec![0; size];
        (self.rand)().fill_bytes(&mut bytes);
        bytes
    }

    fn parameters(&self) -> Asn1Object {
        match self.kind {
            Kind::Iv(size) => Asn1Object::OctetString(Asn1OctetString::new(&self.random(size))),
            Kind::Gcm => object(
                &GcmParameters::new(
                    Asn1OctetString::new(&self.random(NONCE_SIZE)),
                    TAG_SIZE as u8,
                )
                .expect("a nonce of 12 bytes and a tag of 16 are valid"),
            ),
            Kind::Ccm => object(
                &CcmParameters::new(
                    Asn1OctetString::new(&self.random(NONCE_SIZE)),
                    TAG_SIZE as u8,
                )
                .expect("a nonce of 12 bytes and a tag of 16 are valid"),
            ),
            Kind::ChaCha20Poly1305 => {
                Asn1Object::OctetString(Asn1OctetString::new(&self.random(NONCE_SIZE)))
            }
        }
    }
}

impl CipherEntry for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn cipher(&self) -> &str {
        self.cipher
    }

    fn oid(&self) -> &Asn1Oid {
        &self.oid
    }

    fn generate(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::with_parameters(self.oid.clone(), self.parameters())
    }

    fn params(
        &self,
        algorithm: &AlgorithmIdentifier,
        key: &dyn Params,
    ) -> Result<Box<dyn Params>, AlgoAsn1Error> {
        let key = key
            .as_any()
            .downcast_ref::<KeyOwned>()
            .map(KeyParams::key)
            .filter(|key| key.len() == self.key_size)
            .ok_or(AlgoAsn1Error::InvalidKey)?
            .to_vec();
        let parameters = algorithm
            .parameters()
            .ok_or(AlgoAsn1Error::InvalidCipherParameters)?;
        Ok(match self.kind {
            Kind::Iv(size) => {
                let iv = octets(parameters).filter(|iv| iv.len() == size);
                let iv = iv.ok_or(AlgoAsn1Error::InvalidCipherParameters)?;
                Box::new(KeyWithIvOwned::new(key, iv))
            }
            Kind::Gcm => {
                let gcm = read::<GcmParameters>(parameters)?;
                aead(key, gcm.nonce().as_bytes(), gcm.icv_len())
            }
            Kind::Ccm => {
                let ccm = read::<CcmParameters>(parameters)?;
                aead(key, ccm.nonce().as_bytes(), ccm.icv_len())
            }
            Kind::ChaCha20Poly1305 => {
                let nonce = octets(parameters).filter(|nonce| nonce.len() == NONCE_SIZE);
                let nonce = nonce.ok_or(AlgoAsn1Error::InvalidCipherParameters)?;
                Box::new(AeadParamsOwned::new(key, nonce, TAG_SIZE, Vec::new()))
            }
        })
    }
}

fn aead(key: Vec<u8>, nonce: &[u8], tag_size: u8) -> Box<dyn Params> {
    Box::new(AeadParamsOwned::new(
        key,
        nonce.to_vec(),
        usize::from(tag_size),
        Vec::new(),
    ))
}

fn octets(parameters: &Asn1Object) -> Option<Vec<u8>> {
    match parameters {
        Asn1Object::OctetString(octets) => Some(octets.as_bytes().to_vec()),
        _ => None,
    }
}

fn object<T: Encode>(value: &T) -> Asn1Object {
    let der = value
        .encode_to_vec(&EncodingOptions::DER)
        .expect("the parameters of the rows encode");
    decode_all(&der).expect("the parameters of the rows read back")
}

fn read<T: Decode>(parameters: &Asn1Object) -> Result<T, AlgoAsn1Error> {
    let der = parameters.encode_to_vec(&EncodingOptions::DER)?;
    decode_all(&der).map_err(|_| AlgoAsn1Error::InvalidCipherParameters)
}

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().expect("the OIDs of the rows are valid")
}

struct Rows {
    rand: fn() -> Box<dyn CryptoRng>,
    rows: Vec<Box<dyn CipherEntry>>,
}

impl Rows {
    fn new(context: &DefaultAlgoAsn1Context) -> Self {
        Self {
            rand: context.rand(),
            rows: Vec::new(),
        }
    }

    fn add(
        mut self,
        name: &'static str,
        cipher: &'static str,
        dotted: &str,
        key_size: usize,
        kind: Kind,
    ) -> Self {
        self.rows.push(Box::new(Row {
            name,
            cipher,
            oid: oid(dotted),
            key_size,
            kind,
            rand: self.rand,
        }));
        self
    }
}

// NIST CSOR: CBC as RFC 3565 has it, GCM and CCM as RFC 5084
fn aes(context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn CipherEntry>> {
    const CBC: &str = "AES/CBC/PKCS7PADDING";
    const GCM: &str = "AES/GCM/NOPADDING";
    const CCM: &str = "AES/CCM/NOPADDING";
    Rows::new(context)
        .add(
            "AES-128-CBC",
            CBC,
            "2.16.840.1.101.3.4.1.2",
            16,
            Kind::Iv(16),
        )
        .add(
            "AES-192-CBC",
            CBC,
            "2.16.840.1.101.3.4.1.22",
            24,
            Kind::Iv(16),
        )
        .add(
            "AES-256-CBC",
            CBC,
            "2.16.840.1.101.3.4.1.42",
            32,
            Kind::Iv(16),
        )
        .add("AES-128-GCM", GCM, "2.16.840.1.101.3.4.1.6", 16, Kind::Gcm)
        .add("AES-192-GCM", GCM, "2.16.840.1.101.3.4.1.26", 24, Kind::Gcm)
        .add("AES-256-GCM", GCM, "2.16.840.1.101.3.4.1.46", 32, Kind::Gcm)
        .add("AES-128-CCM", CCM, "2.16.840.1.101.3.4.1.7", 16, Kind::Ccm)
        .add("AES-192-CCM", CCM, "2.16.840.1.101.3.4.1.27", 24, Kind::Ccm)
        .add("AES-256-CCM", CCM, "2.16.840.1.101.3.4.1.47", 32, Kind::Ccm)
        .rows
}

// DES-CBC of OIW and DES-EDE3-CBC of RFC 3370, with three keys
fn des(context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn CipherEntry>> {
    Rows::new(context)
        .add(
            "DES-CBC",
            "DES/CBC/PKCS7PADDING",
            "1.3.14.3.2.7",
            8,
            Kind::Iv(8),
        )
        .add(
            "DES-EDE3-CBC",
            "DESEDE/CBC/PKCS7PADDING",
            "1.2.840.113549.3.7",
            24,
            Kind::Iv(8),
        )
        .rows
}

// RFC 3657
fn camellia(context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn CipherEntry>> {
    const CBC: &str = "CAMELLIA/CBC/PKCS7PADDING";
    Rows::new(context)
        .add(
            "CAMELLIA-128-CBC",
            CBC,
            "1.2.392.200011.61.1.1.1.2",
            16,
            Kind::Iv(16),
        )
        .add(
            "CAMELLIA-192-CBC",
            CBC,
            "1.2.392.200011.61.1.1.1.3",
            24,
            Kind::Iv(16),
        )
        .add(
            "CAMELLIA-256-CBC",
            CBC,
            "1.2.392.200011.61.1.1.1.4",
            32,
            Kind::Iv(16),
        )
        .rows
}

// RFC 4010
fn seed(context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn CipherEntry>> {
    Rows::new(context)
        .add(
            "SEED-CBC",
            "SEED/CBC/PKCS7PADDING",
            "1.2.410.200004.1.4",
            16,
            Kind::Iv(16),
        )
        .rows
}

// RFC 5794
fn aria(context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn CipherEntry>> {
    const CBC: &str = "ARIA/CBC/PKCS7PADDING";
    Rows::new(context)
        .add(
            "ARIA-128-CBC",
            CBC,
            "1.2.410.200046.1.1.2",
            16,
            Kind::Iv(16),
        )
        .add(
            "ARIA-192-CBC",
            CBC,
            "1.2.410.200046.1.1.7",
            24,
            Kind::Iv(16),
        )
        .add(
            "ARIA-256-CBC",
            CBC,
            "1.2.410.200046.1.1.12",
            32,
            Kind::Iv(16),
        )
        .rows
}

// GM/T 0006
fn sm4(context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn CipherEntry>> {
    Rows::new(context)
        .add(
            "SM4-CBC",
            "SM4/CBC/PKCS7PADDING",
            "1.2.156.10197.1.104.2",
            16,
            Kind::Iv(16),
        )
        .rows
}

// RFC 8103
fn chacha20_poly1305(context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn CipherEntry>> {
    Rows::new(context)
        .add(
            "CHACHA20-POLY1305",
            "CHACHA20-POLY1305",
            "1.2.840.113549.1.9.16.3.18",
            32,
            Kind::ChaCha20Poly1305,
        )
        .rows
}
