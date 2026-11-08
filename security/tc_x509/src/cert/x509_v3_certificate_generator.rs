use chrono::{DateTime, TimeDelta, Utc};
use tc_asn1::{Asn1Error, Asn1Integer, Asn1Oid};
use tc_asn1_x500::Name;
use tc_asn1_x509::{
    cert::{SubjectPublicKeyInfo, Time, Validity},
    ext::Extension,
};

use crate::X509Error;

/// BC's `X509V3CertificateGenerator`: the fields of a version 3 certificate to be signed. A
/// missing field is reported when the certificate is generated. Every method is variable time,
/// for public values only.
#[derive(Clone, Debug, Default)]
pub struct X509V3CertificateGenerator {
    serial_number: Option<Asn1Integer>,
    issuer: Option<Name>,
    not_before: Option<Time>,
    not_after: Option<Time>,
    subject: Option<Name>,
    subject_public_key_info: Option<SubjectPublicKeyInfo>,
    extensions: Vec<Extension>,
}

impl X509V3CertificateGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    /// `InvalidSerialNumber` unless it is a positive integer, as BC's `SetSerialNumber` checks.
    pub fn set_serial_number(&mut self, serial_number: Asn1Integer) -> Result<(), X509Error> {
        if serial_number.is_negative() || serial_number.as_bytes() == [0] {
            return Err(X509Error::InvalidSerialNumber);
        }
        self.serial_number = Some(serial_number);
        Ok(())
    }

    /// Back to a random serial number, made when the certificate is generated.
    pub fn clear_serial_number(&mut self) {
        self.serial_number = None;
    }

    pub fn set_issuer(&mut self, issuer: Name) {
        self.issuer = Some(issuer);
    }

    /// The issuer from a string such as `"CN=My CA,O=Acme"`; `Asn1` when it does not parse.
    pub fn set_issuer_by_str(&mut self, issuer: &str) -> Result<(), X509Error> {
        self.issuer = Some(issuer.parse()?);
        Ok(())
    }

    pub fn clear_issuer(&mut self) {
        self.issuer = None;
    }

    pub fn set_validity(&mut self, validity: Validity) {
        self.not_before = Some(validity.not_before());
        self.not_after = Some(validity.not_after());
    }

    /// Valid from now, to the second, for `days` days; `Asn1` when the end falls past 9999.
    pub fn set_validity_days(&mut self, days: u32) -> Result<(), X509Error> {
        let now = Utc::now();
        let end = now
            .checked_add_signed(TimeDelta::days(i64::from(days)))
            .ok_or(Asn1Error::MalformedValue)?;
        self.not_before = Some(Time::try_from(now)?);
        self.not_after = Some(Time::try_from(end)?);
        Ok(())
    }

    /// Valid from `not_before` to `not_after`, to the second; `Asn1` when either falls outside
    /// 1950-9999 or the end comes before the start, as `Validity::new` checks.
    pub fn set_validity_by_datetime(
        &mut self,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
    ) -> Result<(), X509Error> {
        let validity = Validity::new(Time::try_from(not_before)?, Time::try_from(not_after)?)?;
        self.set_validity(validity);
        Ok(())
    }

    /// Clears both ends of the validity.
    pub fn clear_validity(&mut self) {
        self.not_before = None;
        self.not_after = None;
    }

    /// The start of the validity. Whether it comes before the end is checked when the certificate
    /// is generated, as the end may not be set yet.
    pub fn set_not_before(&mut self, not_before: Time) {
        self.not_before = Some(not_before);
    }

    /// The start of the validity, to the second; `Asn1` when it falls outside 1950-9999.
    pub fn set_not_before_by_datetime(
        &mut self,
        not_before: DateTime<Utc>,
    ) -> Result<(), X509Error> {
        self.not_before = Some(Time::try_from(not_before)?);
        Ok(())
    }

    pub fn clear_not_before(&mut self) {
        self.not_before = None;
    }

    /// The end of the validity. Whether it comes after the start is checked when the certificate
    /// is generated, as the start may not be set yet.
    pub fn set_not_after(&mut self, not_after: Time) {
        self.not_after = Some(not_after);
    }

    /// The end of the validity, to the second; `Asn1` when it falls outside 1950-9999.
    pub fn set_not_after_by_datetime(&mut self, not_after: DateTime<Utc>) -> Result<(), X509Error> {
        self.not_after = Some(Time::try_from(not_after)?);
        Ok(())
    }

    pub fn clear_not_after(&mut self) {
        self.not_after = None;
    }

    pub fn set_subject(&mut self, subject: Name) {
        self.subject = Some(subject);
    }

    /// The subject from a string such as `"CN=Alice,O=Acme"`; `Asn1` when it does not parse.
    pub fn set_subject_by_str(&mut self, subject: &str) -> Result<(), X509Error> {
        self.subject = Some(subject.parse()?);
        Ok(())
    }

    pub fn clear_subject(&mut self) {
        self.subject = None;
    }

    pub fn set_subject_public_key_info(&mut self, subject_public_key_info: SubjectPublicKeyInfo) {
        self.subject_public_key_info = Some(subject_public_key_info);
    }

    pub fn clear_subject_public_key_info(&mut self) {
        self.subject_public_key_info = None;
    }

    /// `DuplicateExtension` when one with the same OID is already added, as RFC 5280 section 4.2
    /// allows each extension only once. Remove the old one first to replace it.
    pub fn add_extension(&mut self, extension: Extension) -> Result<(), X509Error> {
        if self
            .extensions
            .iter()
            .any(|added| added.extn_id() == extension.extn_id())
        {
            return Err(X509Error::DuplicateExtension);
        }
        self.extensions.push(extension);
        Ok(())
    }

    /// Takes out the extension with the OID, and returns whether there was one.
    pub fn remove_extension(&mut self, oid: &Asn1Oid) -> bool {
        let before = self.extensions.len();
        self.extensions
            .retain(|extension| extension.extn_id() != oid);
        self.extensions.len() != before
    }

    /// Takes out every extension added.
    pub fn clear_extensions(&mut self) {
        self.extensions.clear();
    }
}
