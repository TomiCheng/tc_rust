use tc_algo::Params;
use tc_algo::params::key::{X448PublicKey, X25519PublicKey};
use tc_asn1::{Asn1BitString, NamedOid};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::spki::SpkiEntry;
use crate::{AlgoAsn1Error, DefaultAlgoAsn1Context};

// id-X25519 and id-X448 of RFC 8410
const ID_X25519: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x6e], "1.3.101.110", "id-X25519");
const ID_X448: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x6f], "1.3.101.111", "id-X448");

// One row each for X25519 and X448
pub(super) fn xdh(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn SpkiEntry>> {
    vec![Box::new(X25519), Box::new(X448)]
}

struct X25519;

struct X448;

macro_rules! xdh_row {
    ($row:ty, $key:ty, $id:ident, $len:literal) => {
        impl SpkiEntry for $row {
            // No parameters, and the raw bytes of u in the BIT STRING, as RFC 8410 and Bouncy Castle's
            // SubjectPublicKeyInfoFactory
            fn encode(
                &self,
                key: &dyn Params,
            ) -> Option<Result<SubjectPublicKeyInfo, AlgoAsn1Error>> {
                let key = key.as_any().downcast_ref::<$key>()?;
                Some(Ok(SubjectPublicKeyInfo::new(
                    AlgorithmIdentifier::new($id.oid()),
                    Asn1BitString::from_bytes(key.u()),
                )))
            }

            // RFC 8410 has the parameters absent; any, or a key of another length, is refused
            fn decode(
                &self,
                spki: &SubjectPublicKeyInfo,
            ) -> Option<Result<Box<dyn Params>, AlgoAsn1Error>> {
                if $id != *spki.algorithm().algorithm() {
                    return None;
                }
                let bits = spki.subject_public_key();
                if spki.algorithm().parameters().is_some() || bits.unused_bits() != 0 {
                    return Some(Err(AlgoAsn1Error::InvalidPublicKey));
                }
                let Ok(u) = <[u8; $len]>::try_from(bits.as_bytes()) else {
                    return Some(Err(AlgoAsn1Error::InvalidPublicKey));
                };
                Some(Ok(Box::new(<$key>::new(u))))
            }
        }
    };
}

xdh_row!(X25519, X25519PublicKey, ID_X25519, 32);
xdh_row!(X448, X448PublicKey, ID_X448, 56);
