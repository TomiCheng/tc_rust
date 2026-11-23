use tc_asn1::{Encode, EncodingOptions};
use tc_asn1_cmp::crmf::PkMacValue;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::{CrmfError, PkMacBuilder};

pub struct PkMacValueVerifier<'a, 'provider> {
    builder: &'a PkMacBuilder<'provider>,
}

impl<'a, 'provider> PkMacValueVerifier<'a, 'provider> {
    pub fn new(builder: &'a PkMacBuilder<'provider>) -> Self {
        Self { builder }
    }

    pub fn is_valid(
        &self,
        value: &PkMacValue,
        password: &str,
        public_key: &SubjectPublicKeyInfo,
    ) -> Result<bool, CrmfError> {
        if value.value().unused_bits() != 0 {
            return Ok(false);
        }
        let mac = self.builder.get(value.alg_id(), password)?;
        let encoded = public_key.encode_to_vec(&EncodingOptions::DER)?;
        mac.verify(&encoded, value.value().as_bytes())
    }
}
