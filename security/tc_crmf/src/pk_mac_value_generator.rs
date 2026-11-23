use tc_asn1::{Asn1BitString, Encode, EncodingOptions};
use tc_asn1_cmp::crmf::PkMacValue;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::{CrmfError, PkMacBuilder};

pub struct PkMacValueGenerator;

impl PkMacValueGenerator {
    pub fn generate(
        builder: &PkMacBuilder<'_>,
        password: &str,
        public_key: &SubjectPublicKeyInfo,
    ) -> Result<PkMacValue, CrmfError> {
        let mac = builder.build(password)?;
        let encoded = public_key.encode_to_vec(&EncodingOptions::DER)?;
        Ok(PkMacValue::new(
            mac.algorithm().clone(),
            Asn1BitString::from_bytes(&mac.calculate(&encoded)?),
        ))
    }
}
