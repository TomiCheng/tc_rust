use std::io::Write;

use chrono::{DateTime, TimeDelta, Utc};
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_asn1::{Asn1BitString, Asn1Error, Asn1Integer, Asn1Oid, Encode, EncodingOptions};
use tc_asn1_x500::Name;
use tc_asn1_x509::{
    cert::{Certificate, SubjectPublicKeyInfo, TbsCertificate, Time, Validity, Version},
    ext::{BasicConstraints, Extension, ExtensionId, Extensions, KeyUsage},
    name::{GeneralName, GeneralNames},
};

use crate::X509Error;
use crate::cert::X509Certificate;
use crate::operator::signer::SignatureFactory;

// The length of a serial number made when none is set, as BC advises: 16 bytes of secure random
// data, with the top bit clear so that the number is positive
const RANDOM_SERIAL_BYTES: usize = 16;

pub(super) fn random_serial_number() -> Asn1Integer {
    let mut rng = UnwrapErr(SysRng);
    let mut bytes = [0; RANDOM_SERIAL_BYTES];
    loop {
        rng.fill_bytes(&mut bytes);
        bytes[0] &= 0x7f;
        if bytes.iter().any(|&byte| byte != 0) {
            return Asn1Integer::from_unsigned_bytes(&bytes);
        }
    }
}

// The extensions of an alternative key and signature, which BC does not copy from a template
fn is_alternative(oid: &Asn1Oid) -> bool {
    [
        ExtensionId::SUBJECT_ALT_PUBLIC_KEY_INFO,
        ExtensionId::ALT_SIGNATURE_ALGORITHM,
        ExtensionId::ALT_SIGNATURE_VALUE,
    ]
    .iter()
    .any(|known| *known == *oid)
}

/// BC's `X509V3CertificateGenerator`: the fields of a version 3 certificate to be signed. A
/// missing field is reported when the certificate is generated. Every method is variable time,
/// for public values only.
///
#[doc = include_str!("../../docs/X509CertificateV3Generator.md")]
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

    /// Starts from a certificate, as BC's constructor with a template does: the serial number,
    /// issuer, validity, subject, public key and extensions are copied, except the extensions of
    /// an alternative key and signature, which belong to the old signature. The serial number is
    /// the template's, so clear it for a new certificate from the same issuer.
    pub fn from_certificate(template: &Certificate) -> Self {
        let tbs = template.tbs();
        let validity = tbs.validity();
        let extensions = tbs
            .extensions()
            .map(|extensions| {
                extensions
                    .extensions()
                    .iter()
                    .filter(|extension| !is_alternative(extension.extn_id()))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Self {
            serial_number: Some(tbs.serial_number().clone()),
            issuer: Some(tbs.issuer().clone()),
            not_before: Some(validity.not_before()),
            not_after: Some(validity.not_after()),
            subject: Some(tbs.subject().clone()),
            subject_public_key_info: Some(tbs.subject_public_key_info().clone()),
            extensions,
        }
    }

    /// `from_certificate` with the certificate an `X509Certificate` holds.
    pub fn from_x509_certificate(template: &X509Certificate) -> Self {
        Self::from_certificate(template.certificate())
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

    /// Whether the subject is a CA, marked critical as RFC 5280 section 4.2.1.9 requires of a
    /// CA; `BasicConstraints::end_entity()` for any other.
    pub fn add_basic_constraints(&mut self, value: BasicConstraints) -> Result<(), X509Error> {
        self.add_extension(Extension::with_value(
            ExtensionId::BASIC_CONSTRAINTS,
            true,
            &value,
        )?)
    }

    /// What the key may be used for, such as `KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN`,
    /// marked critical as RFC 5280 section 4.2.1.3 recommends.
    pub fn add_key_usage(&mut self, value: KeyUsage) -> Result<(), X509Error> {
        self.add_extension(Extension::with_value(ExtensionId::KEY_USAGE, true, &value)?)
    }

    /// The other names of the subject, such as its DNS names, not marked critical. A certificate
    /// with an empty subject needs this marked critical, so add it with `add_extension` then, as
    /// RFC 5280 section 4.2.1.6 requires.
    pub fn add_subject_alt_name(&mut self, value: GeneralNames) -> Result<(), X509Error> {
        self.add_extension(Extension::with_value(
            ExtensionId::SUBJECT_ALT_NAME,
            false,
            &value,
        )?)
    }

    /// `add_subject_alt_name` with DNS names only, such as `&["example.com", "www.example.com"]`;
    /// `Asn1` when the list is empty or a name is not an IA5String.
    pub fn add_subject_alt_name_dns(&mut self, names: &[&str]) -> Result<(), X509Error> {
        let names = names
            .iter()
            .map(|name| GeneralName::dns_name(name))
            .collect::<Result<Vec<_>, _>>()?;
        self.add_subject_alt_name(GeneralNames::new(names)?)
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

    /// Signs the fields into a certificate, as BC's `Generate` does. `MissingField` names a field
    /// not set; the subject may be left out only when a critical subject alternative name is
    /// added. An end of the validity before its start is `Asn1`. Without a serial number, a random
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

    fn tbs(
        &self,
        signature: tc_asn1_x509::alg::AlgorithmIdentifier,
    ) -> Result<TbsCertificate, X509Error> {
        let issuer = self
            .issuer
            .clone()
            .ok_or(X509Error::MissingField("issuer"))?;
        let not_before = self
            .not_before
            .ok_or(X509Error::MissingField("not_before"))?;
        let not_after = self.not_after.ok_or(X509Error::MissingField("not_after"))?;
        let subject = match &self.subject {
            Some(subject) => subject.clone(),
            None if self.has_critical_subject_alt_name() => Name::new(Vec::new()),
            None => return Err(X509Error::MissingField("subject")),
        };
        let subject_public_key_info = self
            .subject_public_key_info
            .clone()
            .ok_or(X509Error::MissingField("subject_public_key_info"))?;
        let serial_number = self
            .serial_number
            .clone()
            .unwrap_or_else(random_serial_number);

        let tbs = TbsCertificate::new(
            Version::V3,
            serial_number,
            signature,
            issuer,
            Validity::new(not_before, not_after)?,
            subject,
            subject_public_key_info,
        );
        if self.extensions.is_empty() {
            return Ok(tbs);
        }
        Ok(tbs.with_extensions(Extensions::new(self.extensions.clone())?)?)
    }

    fn has_critical_subject_alt_name(&self) -> bool {
        self.extensions.iter().any(|extension| {
            ExtensionId::SUBJECT_ALT_NAME == *extension.extn_id() && extension.critical()
        })
    }
}
