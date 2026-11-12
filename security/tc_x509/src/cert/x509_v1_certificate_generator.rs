use std::io::Write;

use chrono::{DateTime, TimeDelta, Utc};
use tc_asn1::{Asn1BitString, Asn1Error, Asn1Integer, Encode, EncodingOptions};
use tc_asn1_x500::Name;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::{
    Certificate, SubjectPublicKeyInfo, TbsCertificate, Time, Validity, Version,
};

use super::x509_v3_certificate_generator::random_serial_number;
use crate::X509Error;
use crate::cert::X509Certificate;
use crate::operator::signer::SignatureFactory;

/// BC's `X509V1CertificateGenerator`: the fields of a version 1 certificate to be signed, which
/// has no extensions. A missing field is reported when the certificate is generated. Every method
/// is variable time, for public values only.
///
#[doc = include_str!("../../docs/X509CertificateV1Generator.md")]
#[derive(Clone, Debug, Default)]
pub struct X509V1CertificateGenerator {
    serial_number: Option<Asn1Integer>,
    issuer: Option<Name>,
    not_before: Option<Time>,
    not_after: Option<Time>,
    subject: Option<Name>,
    subject_public_key_info: Option<SubjectPublicKeyInfo>,
}

impl X509V1CertificateGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears every field, as BC's `Reset` does, leaving the generator as `new` makes it.
    pub fn reset(&mut self) {
        *self = Self::new();
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

    /// Signs the fields into a certificate, as BC's `Generate` does. `MissingField` names a field
    /// not set, the subject included, as a version 1 certificate has no alternative name to stand
    /// for it. An end of the validity before its start is `Asn1`. Without a serial number, a random
    /// one of 16 bytes is made, so each call gives a different certificate. The signature
    /// algorithm of the factory goes into the signed part. The generator is left as it was.
    pub fn generate(&self, factory: &dyn SignatureFactory) -> Result<X509Certificate, X509Error> {
        let tbs = self.tbs(factory.algorithm().clone())?;
        let der = tbs.encode_to_vec(&EncodingOptions::DER)?;

        let mut calculator = factory.create_calculator()?;
        calculator.write_all(&der)?;
        let signature = calculator.result().collect()?;

        let certificate = Certificate::new(tbs, Asn1BitString::from_bytes(&signature))?;
        Ok(X509Certificate::new(certificate))
    }

    fn tbs(&self, signature: AlgorithmIdentifier) -> Result<TbsCertificate, X509Error> {
        let issuer = self
            .issuer
            .clone()
            .ok_or(X509Error::MissingField("issuer"))?;
        let not_before = self
            .not_before
            .ok_or(X509Error::MissingField("not_before"))?;
        let not_after = self.not_after.ok_or(X509Error::MissingField("not_after"))?;
        let subject = self
            .subject
            .clone()
            .ok_or(X509Error::MissingField("subject"))?;
        let subject_public_key_info = self
            .subject_public_key_info
            .clone()
            .ok_or(X509Error::MissingField("subject_public_key_info"))?;
        let serial_number = self
            .serial_number
            .clone()
            .unwrap_or_else(random_serial_number);

        Ok(TbsCertificate::new(
            Version::V1,
            serial_number,
            signature,
            issuer,
            Validity::new(not_before, not_after)?,
            subject,
            subject_public_key_info,
        ))
    }
}
