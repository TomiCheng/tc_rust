use tc_algo::Params;
use tc_algo::params::key::{DsaParameters, DsaPrivateKey};
use tc_asn1::{
    Asn1Integer, Asn1Object, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions,
    NamedOid,
};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x509::alg::{AlgorithmIdentifier, DsaParameter};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_zeroize::Zeroizing;

use super::decode_all;
use crate::private_key_info::PrivateKeyInfoEntry;
use crate::{AlgoAsn1Error, DefaultAlgoAsn1Context};

// id-dsa of RFC 3279
const ID_DSA: NamedOid = NamedOid::new(
    &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01],
    "1.2.840.10040.4.1",
    "id-dsa",
);

// DSA 的列，認得 DsaPrivateKey
pub(super) fn dsa(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn PrivateKeyInfoEntry>> {
    vec![Box::new(Dsa)]
}

struct Dsa;

impl PrivateKeyInfoEntry for Dsa {
    // id-dsa 帶 Dss-Parms 的 p、q、g，私鑰是 x 的 INTEGER，同 BC 的 PrivateKeyInfoFactory
    fn encode(&self, key: &dyn Params) -> Option<Result<PrivateKeyInfo, AlgoAsn1Error>> {
        let key = key.as_any().downcast_ref::<DsaPrivateKey>()?;
        Some(info(key))
    }

    // BC 的 PrivateKeyFactory 允許沒有參數，但這裡的 DsaPrivateKey 一定要有，所以是 InvalidPrivateKey
    fn decode(&self, info: &PrivateKeyInfo) -> Option<Result<Box<dyn Params>, AlgoAsn1Error>> {
        if ID_DSA != *info.algorithm().algorithm() {
            return None;
        }
        Some(key(info))
    }
}

fn info(key: &DsaPrivateKey) -> Result<PrivateKeyInfo, AlgoAsn1Error> {
    let params = key.params();
    let parameter = DsaParameter::new(
        integer(params.p()),
        integer(params.q()),
        integer(params.g()),
    );
    let der = parameter.encode_to_vec(&EncodingOptions::DER)?;
    let (_, object) = Asn1Object::decode(&der, &DecodingOptions::default())?;
    let x = Zeroizing::new(integer(key.x()).encode_to_vec(&EncodingOptions::DER)?);
    Ok(PrivateKeyInfo::new(
        AlgorithmIdentifier::with_parameters(ID_DSA.oid(), object),
        Asn1OctetString::new(&x),
    ))
}

fn key(info: &PrivateKeyInfo) -> Result<Box<dyn Params>, AlgoAsn1Error> {
    let Some(parameters) = info.algorithm().parameters() else {
        return Err(AlgoAsn1Error::InvalidPrivateKey);
    };
    let der = parameters.encode_to_vec(&EncodingOptions::DER)?;
    let parameter: DsaParameter = decode_all(&der)?;
    let x: Asn1Integer = decode_all(info.private_key().as_bytes())?;
    if x.is_negative() {
        return Err(AlgoAsn1Error::InvalidPrivateKey);
    }
    // 與 SPKI 那一列相同，都補到 p 的寬度
    let width = parameter.p().as_unsigned_bytes()?.len();
    let params = DsaParameters::new(
        padded(parameter.p(), width)?,
        padded(parameter.q(), width)?,
        padded(parameter.g(), width)?,
    );
    Ok(Box::new(DsaPrivateKey::new(padded(&x, width)?, params)))
}

fn integer(value: &PaddedBigUint) -> Asn1Integer {
    Asn1Integer::from_unsigned_bytes(&ArrayEncoding::<u8>::to_be(value))
}

fn padded(value: &Asn1Integer, width: usize) -> Result<PaddedBigUint, AlgoAsn1Error> {
    let bytes = value.as_unsigned_bytes()?;
    let mut buffer = Zeroizing::new(vec![0; width.max(bytes.len())]);
    let start = buffer.len() - bytes.len();
    buffer[start..].copy_from_slice(bytes);
    let Ok(value) = PaddedBigUint::from_be(&buffer[..]);
    Ok(value)
}
