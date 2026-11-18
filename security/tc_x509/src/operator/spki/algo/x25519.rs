use tc_algo::Params;
use tc_algo::params::key::cfrg::X25519PublicKey;
use tc_asn1::{Asn1BitString, NamedOid};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::operator::spki::SpkiEntry;
use crate::{DefaultX509OperatorContext, X509Error};

// id-X25519 of RFC 8410
const ID_X25519: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x6e], "1.3.101.110", "id-X25519");

// The row of X25519, which knows an X25519PublicKey
pub(super) fn x25519(_context: &DefaultX509OperatorContext) -> Vec<Box<dyn SpkiEntry>> {
    vec![Box::new(X25519)]
}

struct X25519;

impl SpkiEntry for X25519 {
    // id-X25519 with no parameters, and the 32 bytes of u in the BIT STRING, as RFC 8410 and
    // Bouncy Castle's SubjectPublicKeyInfoFactory write it
    fn encode(&self, key: &dyn Params) -> Option<Result<SubjectPublicKeyInfo, X509Error>> {
        let key = key.as_any().downcast_ref::<X25519PublicKey>()?;
        Some(Ok(SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(ID_X25519.oid()),
            Asn1BitString::from_bytes(key.u()),
        )))
    }

    // RFC 8410 has the parameters absent; any, or a key of another length, is refused
    fn decode(&self, spki: &SubjectPublicKeyInfo) -> Option<Result<Box<dyn Params>, X509Error>> {
        if ID_X25519 != *spki.algorithm().algorithm() {
            return None;
        }
        let bits = spki.subject_public_key();
        if spki.algorithm().parameters().is_some() || bits.unused_bits() != 0 {
            return Some(Err(X509Error::InvalidPublicKey));
        }
        let Ok(u) = <[u8; 32]>::try_from(bits.as_bytes()) else {
            return Some(Err(X509Error::InvalidPublicKey));
        };
        Some(Ok(Box::new(X25519PublicKey::new(u))))
    }
}
