use tc_asn1::{Asn1Oid, Asn1Utf8String, Encode};
use tc_asn1_cmp::crmf::{
    AttributeTypeAndValue, CertId, CrmfId, PkiArchiveOptions, PkiPublicationInfo,
};
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::{CrmfError, der};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Control {
    RegToken(Asn1Utf8String),
    Authenticator(Asn1Utf8String),
    PkiPublicationInfo(PkiPublicationInfo),
    PkiArchive(Box<PkiArchiveOptions>),
    OldCertId(CertId),
    ProtocolEncrKey(SubjectPublicKeyInfo),
}

impl Control {
    pub fn oid(&self) -> Asn1Oid {
        match self {
            Self::RegToken(_) => CrmfId::REG_TOKEN,
            Self::Authenticator(_) => CrmfId::AUTHENTICATOR,
            Self::PkiPublicationInfo(_) => CrmfId::PKI_PUBLICATION_INFO,
            Self::PkiArchive(_) => CrmfId::PKI_ARCHIVE_OPTIONS,
            Self::OldCertId(_) => CrmfId::OLD_CERT_ID,
            Self::ProtocolEncrKey(_) => CrmfId::PROTOCOL_ENCR_KEY,
        }
        .oid()
    }

    pub fn to_asn1(&self) -> Result<AttributeTypeAndValue, CrmfError> {
        let value: &dyn Encode = match self {
            Self::RegToken(value) | Self::Authenticator(value) => value,
            Self::PkiPublicationInfo(value) => value,
            Self::PkiArchive(value) => value.as_ref(),
            Self::OldCertId(value) => value,
            Self::ProtocolEncrKey(value) => value,
        };
        Ok(AttributeTypeAndValue::new(self.oid(), der::convert(value)?))
    }

    pub(crate) fn decode(attribute: &AttributeTypeAndValue) -> Result<Option<Self>, CrmfError> {
        let oid = attribute.attribute_type();
        let bytes = attribute.value().raw();
        Ok(Some(if *oid == CrmfId::REG_TOKEN.oid() {
            Self::RegToken(der::decode(bytes)?)
        } else if *oid == CrmfId::AUTHENTICATOR.oid() {
            Self::Authenticator(der::decode(bytes)?)
        } else if *oid == CrmfId::PKI_PUBLICATION_INFO.oid() {
            Self::PkiPublicationInfo(der::decode(bytes)?)
        } else if *oid == CrmfId::PKI_ARCHIVE_OPTIONS.oid() {
            Self::PkiArchive(Box::new(der::decode(bytes)?))
        } else if *oid == CrmfId::OLD_CERT_ID.oid() {
            Self::OldCertId(der::decode(bytes)?)
        } else if *oid == CrmfId::PROTOCOL_ENCR_KEY.oid() {
            Self::ProtocolEncrKey(der::decode(bytes)?)
        } else {
            return Ok(None);
        }))
    }
}
