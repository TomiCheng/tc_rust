use std::io::Write;

use chrono::{DateTime, TimeDelta, Utc};
use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1GeneralizedTime, Asn1Integer, Asn1Oid, Encode, EncodingOptions,
};
use tc_asn1_x500::{Attribute, Name};
use tc_asn1_x509::{
    alg::AlgorithmIdentifier,
    attr::{
        AttCertIssuer, AttCertValidityPeriod, AttributeCertificate, AttributeCertificateInfo,
        Holder, IssuerSerial, V2Form,
    },
    ext::{Extension, Extensions},
    name::{GeneralName, GeneralNames},
};

use super::x509_v3_certificate_generator::random_serial_number;
use crate::X509Error;
use crate::cert::{X509AttributeCertificate, X509Certificate};
use crate::operator::signer::SignatureFactory;

fn directory_names(name: Name) -> Result<GeneralNames, X509Error> {
    Ok(GeneralNames::new(vec![GeneralName::DirectoryName(name)])?)
}

/// BC's `X509V2AttributeCertificateGenerator`: the fields of an attribute certificate (RFC 5755)
/// to be signed, which binds attributes such as roles to a holder rather than a public key. A
/// missing field is reported when the certificate is generated. Every method is variable time,
/// for public values only.
#[derive(Clone, Debug, Default)]
pub struct X509V2AttributeCertificateGenerator {
    holder: Option<Holder>,
    issuer: Option<AttCertIssuer>,
    serial_number: Option<Asn1Integer>,
    not_before: Option<Asn1GeneralizedTime>,
    not_after: Option<Asn1GeneralizedTime>,
    attributes: Vec<Attribute>,
    issuer_unique_id: Option<Asn1BitString>,
    extensions: Vec<Extension>,
}

impl X509V2AttributeCertificateGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears every field, as BC's `Reset` does, leaving the generator as `new` makes it.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn set_holder(&mut self, holder: Holder) {
        self.holder = Some(holder);
    }

    /// The holder as the public key certificate it names by issuer and serial number, the
    /// `baseCertificateID` form RFC 5755 section 4.2.2 prefers.
    pub fn set_holder_by_certificate(
        &mut self,
        certificate: &X509Certificate,
    ) -> Result<(), X509Error> {
        let issuer_serial = IssuerSerial::new(
            directory_names(certificate.issuer().clone())?,
            certificate.serial_number().clone(),
        );
        self.holder = Some(Holder::new(Some(issuer_serial), None, None)?);
        Ok(())
    }

    /// The holder by its name, the `entityName` form.
    pub fn set_holder_by_name(&mut self, name: Name) -> Result<(), X509Error> {
        self.holder = Some(Holder::new(None, Some(directory_names(name)?), None)?);
        Ok(())
    }

    /// `set_holder_by_name` from a string such as `"CN=Alice,O=Acme"`; `Asn1` when it does not
    /// parse.
    pub fn set_holder_by_str(&mut self, name: &str) -> Result<(), X509Error> {
        self.set_holder_by_name(name.parse()?)
    }

    pub fn clear_holder(&mut self) {
        self.holder = None;
    }

    pub fn set_issuer(&mut self, issuer: AttCertIssuer) {
        self.issuer = Some(issuer);
    }

    /// The issuer by its name, in the `v2Form` with only an `issuerName` that RFC 5755 section
    /// 4.2.3 requires.
    pub fn set_issuer_by_name(&mut self, name: Name) -> Result<(), X509Error> {
        let form = V2Form::new(Some(directory_names(name)?), None, None)?;
        self.issuer = Some(form.into());
        Ok(())
    }

    /// `set_issuer_by_name` from a string such as `"CN=My AA,O=Acme"`; `Asn1` when it does not
    /// parse.
    pub fn set_issuer_by_str(&mut self, name: &str) -> Result<(), X509Error> {
        self.set_issuer_by_name(name.parse()?)
    }

    pub fn clear_issuer(&mut self) {
        self.issuer = None;
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

    pub fn set_validity(&mut self, validity: AttCertValidityPeriod) {
        self.not_before = Some(*validity.not_before_time());
        self.not_after = Some(*validity.not_after_time());
    }

    /// Valid from now, to the second, for `days` days; `Asn1` when the end falls past 9999.
    pub fn set_validity_days(&mut self, days: u32) -> Result<(), X509Error> {
        let now = Utc::now();
        let end = now
            .checked_add_signed(TimeDelta::days(i64::from(days)))
            .ok_or(Asn1Error::MalformedValue)?;
        self.not_before = Some(Asn1GeneralizedTime::try_from(now)?);
        self.not_after = Some(Asn1GeneralizedTime::try_from(end)?);
        Ok(())
    }

    /// Valid from `not_before` to `not_after`, to the second; `Asn1` when either falls past 9999
    /// or the end comes before the start, as `AttCertValidityPeriod::new` checks.
    pub fn set_validity_by_datetime(
        &mut self,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
    ) -> Result<(), X509Error> {
        let validity = AttCertValidityPeriod::new(
            Asn1GeneralizedTime::try_from(not_before)?,
            Asn1GeneralizedTime::try_from(not_after)?,
        )?;
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
    pub fn set_not_before(&mut self, not_before: Asn1GeneralizedTime) {
        self.not_before = Some(not_before);
    }

    /// The start of the validity, to the second; `Asn1` when it falls past 9999.
    pub fn set_not_before_by_datetime(
        &mut self,
        not_before: DateTime<Utc>,
    ) -> Result<(), X509Error> {
        self.not_before = Some(Asn1GeneralizedTime::try_from(not_before)?);
        Ok(())
    }

    pub fn clear_not_before(&mut self) {
        self.not_before = None;
    }

    /// The end of the validity. Whether it comes after the start is checked when the certificate
    /// is generated, as the start may not be set yet.
    pub fn set_not_after(&mut self, not_after: Asn1GeneralizedTime) {
        self.not_after = Some(not_after);
    }

    /// The end of the validity, to the second; `Asn1` when it falls past 9999.
    pub fn set_not_after_by_datetime(&mut self, not_after: DateTime<Utc>) -> Result<(), X509Error> {
        self.not_after = Some(Asn1GeneralizedTime::try_from(not_after)?);
        Ok(())
    }

    pub fn clear_not_after(&mut self) {
        self.not_after = None;
    }

    /// `DuplicateAttribute` when one of the same type is already added, as RFC 5755 section 4.2.7
    /// allows each type only once; put more values in the one attribute instead.
    pub fn add_attribute(&mut self, attribute: Attribute) -> Result<(), X509Error> {
        if self
            .attributes
            .iter()
            .any(|added| added.attribute_type() == attribute.attribute_type())
        {
            return Err(X509Error::DuplicateAttribute);
        }
        self.attributes.push(attribute);
        Ok(())
    }

    /// Takes out the attribute of the type, and returns whether there was one.
    pub fn remove_attribute(&mut self, attribute_type: &Asn1Oid) -> bool {
        let before = self.attributes.len();
        self.attributes
            .retain(|attribute| attribute.attribute_type() != attribute_type);
        self.attributes.len() != before
    }

    /// Takes out every attribute added.
    pub fn clear_attributes(&mut self) {
        self.attributes.clear();
    }

    /// BC's `SetIssuerUniqueId`. RFC 5755 section 4.2.8 advises against it.
    pub fn set_issuer_unique_id(&mut self, issuer_unique_id: Asn1BitString) {
        self.issuer_unique_id = Some(issuer_unique_id);
    }

    pub fn clear_issuer_unique_id(&mut self) {
        self.issuer_unique_id = None;
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

    /// Signs the fields into an attribute certificate, as BC's `Generate` does. `MissingField`
    /// names a field not set, `attributes` when none is added. An end of the validity before its
    /// start is `Asn1`. Without a serial number, a random one of 16 bytes is made, so each call
    /// gives a different certificate. The signature algorithm of the factory goes into the signed
    /// part. The generator is left as it was.
    pub fn generate(
        &self,
        factory: &dyn SignatureFactory,
    ) -> Result<X509AttributeCertificate, X509Error> {
        let acinfo = self.acinfo(factory.algorithm().clone())?;
        let der = acinfo.encode_to_vec(&EncodingOptions::DER)?;

        let mut calculator = factory.create_calculator()?;
        calculator.write_all(&der)?;
        let signature = calculator.result().collect()?;

        let certificate = AttributeCertificate::new(acinfo, Asn1BitString::from_bytes(&signature))?;
        Ok(X509AttributeCertificate::new(certificate))
    }

    fn acinfo(
        &self,
        signature: AlgorithmIdentifier,
    ) -> Result<AttributeCertificateInfo, X509Error> {
        let holder = self
            .holder
            .clone()
            .ok_or(X509Error::MissingField("holder"))?;
        let issuer = self
            .issuer
            .clone()
            .ok_or(X509Error::MissingField("issuer"))?;
        let not_before = self
            .not_before
            .ok_or(X509Error::MissingField("not_before"))?;
        let not_after = self.not_after.ok_or(X509Error::MissingField("not_after"))?;
        if self.attributes.is_empty() {
            return Err(X509Error::MissingField("attributes"));
        }
        let serial_number = self
            .serial_number
            .clone()
            .unwrap_or_else(random_serial_number);

        let mut acinfo = AttributeCertificateInfo::new(
            holder,
            issuer,
            signature,
            serial_number,
            AttCertValidityPeriod::new(not_before, not_after)?,
            self.attributes.clone(),
        )?;
        if let Some(issuer_unique_id) = &self.issuer_unique_id {
            acinfo = acinfo.with_issuer_unique_id(issuer_unique_id.clone());
        }
        if !self.extensions.is_empty() {
            acinfo = acinfo.with_extensions(Extensions::new(self.extensions.clone())?);
        }
        Ok(acinfo)
    }
}
