use tc_algo::Params;
use tc_algo::params::key::{Ed448PrivateKey, Ed25519PrivateKey, X448PrivateKey, X25519PrivateKey};
use tc_asn1::{Asn1BitString, Asn1OctetString, Asn1Oid, Encode, EncodingOptions, NamedOid};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zeroize::Zeroizing;

use super::decode_all;
use crate::pkcs8::Pkcs8Entry;
use crate::{AlgoAsn1Error, DefaultAlgoAsn1Context};

// The four OIDs of RFC 8410
const ID_X25519: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x6e], "1.3.101.110", "id-X25519");
const ID_X448: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x6f], "1.3.101.111", "id-X448");
const ID_ED25519: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x70], "1.3.101.112", "id-Ed25519");
const ID_ED448: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x71], "1.3.101.113", "id-Ed448");

// Older OIDs Bouncy Castle's PrivateKeyFactory reads too: Cryptlib's X25519 and GNU's Ed25519
const CURVEY25519: NamedOid = NamedOid::new(
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],
    "1.3.6.1.4.1.3029.1.5.1",
    "curvey25519",
);
const GNU_ED25519: NamedOid = NamedOid::new(
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01],
    "1.3.6.1.4.1.11591.15.1",
    "Ed25519",
);

// The private key of one CFRG curve: its OID, an older OID also read, whether the raw key may come
// without its OCTET STRING (Bouncy Castle takes that for X25519 and X448 alone, as Java 11 writes
// them), and the conversions between the key and its raw bytes
struct Cfrg {
    id: NamedOid,
    legacy: Option<NamedOid>,
    bare: bool,
    // The raw private key and the raw public key
    encode: fn(&dyn Params) -> Option<(Zeroizing<Vec<u8>>, Vec<u8>)>,
    decode: fn(&[u8]) -> Option<Box<dyn Params>>,
}

macro_rules! raw {
    ($key:ty, $public:ident) => {
        |key| {
            let key = key.as_any().downcast_ref::<$key>()?;
            let public = key.generate_public_key().$public().to_vec();
            Some((Zeroizing::new(key.k().to_vec()), public))
        }
    };
}

macro_rules! from_raw {
    ($key:ty) => {
        |raw| {
            let k = raw.try_into().ok()?;
            Some(Box::new(<$key>::new(k)) as Box<dyn Params>)
        }
    };
}

// One row for each of the four curves
pub(super) fn cfrg(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn Pkcs8Entry>> {
    vec![
        Box::new(Cfrg {
            id: ID_X25519,
            legacy: Some(CURVEY25519),
            bare: true,
            encode: raw!(X25519PrivateKey, u),
            decode: from_raw!(X25519PrivateKey),
        }),
        Box::new(Cfrg {
            id: ID_X448,
            legacy: None,
            bare: true,
            encode: raw!(X448PrivateKey, u),
            decode: from_raw!(X448PrivateKey),
        }),
        Box::new(Cfrg {
            id: ID_ED25519,
            legacy: Some(GNU_ED25519),
            bare: false,
            encode: raw!(Ed25519PrivateKey, a),
            decode: from_raw!(Ed25519PrivateKey),
        }),
        Box::new(Cfrg {
            id: ID_ED448,
            legacy: None,
            bare: false,
            encode: raw!(Ed448PrivateKey, a),
            decode: from_raw!(Ed448PrivateKey),
        }),
    ]
}

impl Cfrg {
    fn knows(&self, oid: &Asn1Oid) -> bool {
        self.id == *oid || self.legacy.as_ref().is_some_and(|legacy| *legacy == *oid)
    }
}

impl Pkcs8Entry for Cfrg {
    // No parameters, the private key in an OCTET STRING of its own and the public key beside it,
    // version 2 of RFC 5958, as Bouncy Castle's PrivateKeyInfoFactory writes it
    fn encode(&self, key: &dyn Params) -> Option<Result<PrivateKeyInfo, AlgoAsn1Error>> {
        let (private, public) = (self.encode)(key)?;
        Some(info(self.id.oid(), &private, &public))
    }

    fn decode(&self, info: &PrivateKeyInfo) -> Option<Result<Box<dyn Params>, AlgoAsn1Error>> {
        if !self.knows(info.algorithm().algorithm()) {
            return None;
        }
        Some(self.private_key(info))
    }
}

fn info(id: Asn1Oid, private: &[u8], public: &[u8]) -> Result<PrivateKeyInfo, AlgoAsn1Error> {
    let inner = Zeroizing::new(Asn1OctetString::new(private).encode_to_vec(&EncodingOptions::DER)?);
    Ok(
        PrivateKeyInfo::new(AlgorithmIdentifier::new(id), Asn1OctetString::new(&inner))
            .with_public_key(Asn1BitString::from_bytes(public)),
    )
}

impl Cfrg {
    fn private_key(&self, info: &PrivateKeyInfo) -> Result<Box<dyn Params>, AlgoAsn1Error> {
        let octets = info.private_key().as_bytes();
        if self.bare {
            if let Some(key) = (self.decode)(octets) {
                return Ok(key);
            }
        }
        let inner: Asn1OctetString = decode_all(octets)?;
        let raw = Zeroizing::new(inner.as_bytes().to_vec());
        (self.decode)(&raw).ok_or(AlgoAsn1Error::InvalidPrivateKey)
    }
}
