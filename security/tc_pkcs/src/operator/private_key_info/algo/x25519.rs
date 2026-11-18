use tc_algo::Params;
use tc_algo::params::key::cfrg::X25519PrivateKey;
use tc_asn1::{Asn1BitString, Asn1OctetString, Encode, EncodingOptions, NamedOid};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zeroize::Zeroizing;

use super::decode_all;
use crate::operator::private_key_info::PrivateKeyInfoEntry;
use crate::{DefaultPkcsOperatorContext, PkcsError};

// id-X25519 of RFC 8410
const ID_X25519: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x6e], "1.3.101.110", "id-X25519");

// Cryptlib's X25519, which Bouncy Castle's PrivateKeyFactory also reads
const CURVEY25519: NamedOid = NamedOid::new(
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],
    "1.3.6.1.4.1.3029.1.5.1",
    "curvey25519",
);

// The row of X25519, which knows an X25519PrivateKey
pub(super) fn x25519(_context: &DefaultPkcsOperatorContext) -> Vec<Box<dyn PrivateKeyInfoEntry>> {
    vec![Box::new(X25519)]
}

struct X25519;

impl PrivateKeyInfoEntry for X25519 {
    // id-X25519 with no parameters, the 32 bytes in an OCTET STRING of their own, and the public
    // key beside them, version 2 of RFC 5958, as Bouncy Castle's PrivateKeyInfoFactory writes it
    fn encode(&self, key: &dyn Params) -> Option<Result<PrivateKeyInfo, PkcsError>> {
        let key = key.as_any().downcast_ref::<X25519PrivateKey>()?;
        Some(info(key))
    }

    // As Bouncy Castle's PrivateKeyFactory, the 32 bytes are also taken bare, as Java 11 writes
    // them, and Cryptlib's OID too
    fn decode(&self, info: &PrivateKeyInfo) -> Option<Result<Box<dyn Params>, PkcsError>> {
        let oid = info.algorithm().algorithm();
        if ID_X25519 != *oid && CURVEY25519 != *oid {
            return None;
        }
        Some(private_key(info).map(|key| Box::new(key) as Box<dyn Params>))
    }
}

fn info(key: &X25519PrivateKey) -> Result<PrivateKeyInfo, PkcsError> {
    let inner = Zeroizing::new(Asn1OctetString::new(key.k()).encode_to_vec(&EncodingOptions::DER)?);
    let public = key.generate_public_key();
    Ok(PrivateKeyInfo::new(
        AlgorithmIdentifier::new(ID_X25519.oid()),
        Asn1OctetString::new(&inner),
    )
    .with_public_key(Asn1BitString::from_bytes(public.u())))
}

fn private_key(info: &PrivateKeyInfo) -> Result<X25519PrivateKey, PkcsError> {
    let octets = info.private_key().as_bytes();
    let k = if octets.len() == 32 {
        Zeroizing::new(octets.to_vec())
    } else {
        let inner: Asn1OctetString = decode_all(octets)?;
        Zeroizing::new(inner.as_bytes().to_vec())
    };
    let k: [u8; 32] = k[..].try_into().map_err(|_| PkcsError::InvalidPrivateKey)?;
    Ok(X25519PrivateKey::new(k))
}
