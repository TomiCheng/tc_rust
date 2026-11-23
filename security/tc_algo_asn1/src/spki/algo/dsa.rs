use tc_algo::Params;
use tc_algo::params::key::{DsaParameters, DsaPublicKey};
use tc_asn1::{
    Asn1BitString, Asn1Integer, Asn1Object, Decode, DecodingOptions, Encode, EncodingOptions,
    NamedOid,
};
use tc_asn1_x509::alg::{AlgorithmIdentifier, DsaParameter};
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_bigint::{ArrayEncoding, PaddedBigUint};

use crate::spki::SpkiEntry;
use crate::{AlgoAsn1Error, DefaultAlgoAsn1Context};

// id-dsa of RFC 3279
const ID_DSA: NamedOid = NamedOid::new(
    &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01],
    "1.2.840.10040.4.1",
    "id-dsa",
);

// The row of DSA, which knows a DsaPublicKey
pub(super) fn dsa(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn SpkiEntry>> {
    vec![Box::new(Dsa)]
}

struct Dsa;

impl SpkiEntry for Dsa {
    // id-dsa with the Dss-Parms p, q and g, and y as an INTEGER in the BIT STRING, as RFC 3279 and
    // Bouncy Castle's SubjectPublicKeyInfoFactory write it
    fn encode(&self, key: &dyn Params) -> Option<Result<SubjectPublicKeyInfo, AlgoAsn1Error>> {
        let key = key.as_any().downcast_ref::<DsaPublicKey>()?;
        Some(spki(key))
    }

    // A key whose parameters are absent inherits them from its issuer, as RFC 3279 allows; the
    // SPKI alone does not have them, so it is InvalidPublicKey here, as Bouncy Castle's
    // PublicKeyFactory gives a key without parameters that cannot verify on its own
    fn decode(
        &self,
        spki: &SubjectPublicKeyInfo,
    ) -> Option<Result<Box<dyn Params>, AlgoAsn1Error>> {
        if ID_DSA != *spki.algorithm().algorithm() {
            return None;
        }
        Some(key(spki))
    }
}

fn spki(key: &DsaPublicKey) -> Result<SubjectPublicKeyInfo, AlgoAsn1Error> {
    let params = key.params();
    let parameter = DsaParameter::new(
        integer(params.p()),
        integer(params.q()),
        integer(params.g()),
    );
    let der = parameter.encode_to_vec(&EncodingOptions::DER)?;
    let (_, object) = Asn1Object::decode(&der, &DecodingOptions::default())?;
    let y = integer(key.y()).encode_to_vec(&EncodingOptions::DER)?;
    Ok(SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::with_parameters(ID_DSA.oid(), object),
        Asn1BitString::from_bytes(&y),
    ))
}

fn key(spki: &SubjectPublicKeyInfo) -> Result<Box<dyn Params>, AlgoAsn1Error> {
    let Some(parameters) = spki.algorithm().parameters() else {
        return Err(AlgoAsn1Error::InvalidPublicKey);
    };
    let der = parameters.encode_to_vec(&EncodingOptions::DER)?;
    let (_, parameter) = DsaParameter::decode(&der, &DecodingOptions::default())?;
    let bits = spki.subject_public_key();
    if bits.unused_bits() != 0 {
        return Err(AlgoAsn1Error::InvalidPublicKey);
    }
    let (used, y) = Asn1Integer::decode(bits.as_bytes(), &DecodingOptions::default())?;
    if used != bits.as_bytes().len() {
        return Err(AlgoAsn1Error::InvalidPublicKey);
    }
    let width = parameter.p().as_unsigned_bytes()?.len();
    let params = DsaParameters::new(
        padded(parameter.p(), width)?,
        padded(parameter.q(), width)?,
        padded(parameter.g(), width)?,
    );
    Ok(Box::new(DsaPublicKey::new(padded(&y, width)?, params)))
}

fn integer(value: &PaddedBigUint) -> Asn1Integer {
    Asn1Integer::from_unsigned_bytes(&ArrayEncoding::<u8>::to_be(value))
}

fn padded(value: &Asn1Integer, width: usize) -> Result<PaddedBigUint, AlgoAsn1Error> {
    let bytes = value.as_unsigned_bytes()?;
    let mut buffer = vec![0; width.max(bytes.len())];
    let start = buffer.len() - bytes.len();
    buffer[start..].copy_from_slice(bytes);
    let Ok(value) = PaddedBigUint::from_be(&buffer[..]);
    Ok(value)
}
