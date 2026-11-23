use tc_algo::Params;
use tc_algo::params::key::{Ed448PublicKey, Ed25519PublicKey};
use tc_asn1::{Asn1BitString, NamedOid};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::spki::SpkiEntry;
use crate::{AlgoAsn1Error, DefaultAlgoAsn1Context};

// id-Ed25519 and id-Ed448 of RFC 8410
const ID_ED25519: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x70], "1.3.101.112", "id-Ed25519");
const ID_ED448: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x71], "1.3.101.113", "id-Ed448");

// The rows of Ed25519 and Ed448, which know an Ed25519PublicKey and an Ed448PublicKey
pub(super) fn eddsa(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn SpkiEntry>> {
    vec![Box::new(Ed25519), Box::new(Ed448)]
}

struct Ed25519;

impl SpkiEntry for Ed25519 {
    // id-Ed25519 with no parameters, and the 32 bytes of the key in the BIT STRING, as RFC 8410
    // and Bouncy Castle's SubjectPublicKeyInfoFactory write it
    fn encode(&self, key: &dyn Params) -> Option<Result<SubjectPublicKeyInfo, AlgoAsn1Error>> {
        let key = key.as_any().downcast_ref::<Ed25519PublicKey>()?;
        Some(Ok(info(ID_ED25519, key.a())))
    }

    fn decode(
        &self,
        spki: &SubjectPublicKeyInfo,
    ) -> Option<Result<Box<dyn Params>, AlgoAsn1Error>> {
        decode(ID_ED25519, spki, |a| Box::new(Ed25519PublicKey::new(a)))
    }
}

struct Ed448;

impl SpkiEntry for Ed448 {
    // id-Ed448 with no parameters, and the 57 bytes of the key in the BIT STRING
    fn encode(&self, key: &dyn Params) -> Option<Result<SubjectPublicKeyInfo, AlgoAsn1Error>> {
        let key = key.as_any().downcast_ref::<Ed448PublicKey>()?;
        Some(Ok(info(ID_ED448, key.a())))
    }

    fn decode(
        &self,
        spki: &SubjectPublicKeyInfo,
    ) -> Option<Result<Box<dyn Params>, AlgoAsn1Error>> {
        decode(ID_ED448, spki, |a| Box::new(Ed448PublicKey::new(a)))
    }
}

fn info(oid: NamedOid, key: &[u8]) -> SubjectPublicKeyInfo {
    SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::new(oid.oid()),
        Asn1BitString::from_bytes(key),
    )
}

// RFC 8410 has the parameters absent; any, or a key of another length, is refused
fn decode<const N: usize>(
    oid: NamedOid,
    spki: &SubjectPublicKeyInfo,
    key: impl FnOnce([u8; N]) -> Box<dyn Params>,
) -> Option<Result<Box<dyn Params>, AlgoAsn1Error>> {
    if oid != *spki.algorithm().algorithm() {
        return None;
    }
    let bits = spki.subject_public_key();
    if spki.algorithm().parameters().is_some() || bits.unused_bits() != 0 {
        return Some(Err(AlgoAsn1Error::InvalidPublicKey));
    }
    let Ok(a) = <[u8; N]>::try_from(bits.as_bytes()) else {
        return Some(Err(AlgoAsn1Error::InvalidPublicKey));
    };
    Some(Ok(key(a)))
}
