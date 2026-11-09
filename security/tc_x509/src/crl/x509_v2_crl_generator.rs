use std::io::Write;

use chrono::{DateTime, TimeDelta, Utc};
use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1Oid, DecodingContext, DecodingOptions, Encode,
    EncodingOptions,
};
use tc_asn1_x500::Name;
use tc_asn1_x509::{
    cert::{Time, Version},
    crl::{CertificateList, CrlNumber, CrlReason, RevokedCertificate, TbsCertList},
    ext::{AuthorityKeyIdentifier, Extension, ExtensionId, Extensions},
};

use crate::X509Error;
use crate::cert::X509Certificate;
use crate::crl::X509Crl;
use crate::operator::signer::SignatureFactory;

// The next update as set: a time, or a span after the this update, which may itself be the time
// generate runs
#[derive(Clone, Copy, Debug)]
enum NextUpdate {
    At(Time),
    After(TimeDelta),
}

// The extensions of an alternative signature, which BC does not copy from a template
fn is_alternative_signature(oid: &Asn1Oid) -> bool {
    ExtensionId::ALT_SIGNATURE_ALGORITHM == *oid || ExtensionId::ALT_SIGNATURE_VALUE == *oid
}

/// BC's `X509V2CrlGenerator`: the fields of a version 2 CRL to be signed. A missing field is
/// reported when the CRL is generated. Every method is variable time, for public values only.
///
#[doc = include_str!("../../docs/X509V2CrlGenerator.md")]
#[derive(Clone, Debug, Default)]
pub struct X509V2CrlGenerator {
    issuer: Option<Name>,
    this_update: Option<Time>,
    next_update: Option<NextUpdate>,
    entries: Vec<RevokedCertificate>,
    extensions: Vec<Extension>,
}

impl X509V2CrlGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts from another CRL, as BC's constructor with a template does: the issuer, this
    /// update, next update, entries and extensions are copied, except the extensions of an
    /// alternative signature, which belong to the old signature. For the next CRL of the same
    /// issuer, clear or set the this update and the next update, and replace the CRL number.
    pub fn from_crl(template: &X509Crl) -> Self {
        Self::from_certificate_list(template.certificate_list())
    }

    /// `from_crl` with the ASN.1 structure of the CRL.
    pub fn from_certificate_list(template: &CertificateList) -> Self {
        let extensions = template
            .extensions()
            .map(|extensions| {
                extensions
                    .extensions()
                    .iter()
                    .filter(|extension| !is_alternative_signature(extension.extn_id()))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Self {
            issuer: Some(template.issuer().clone()),
            this_update: Some(*template.this_update()),
            next_update: template.next_update().copied().map(NextUpdate::At),
            entries: template.revoked_certificates().to_vec(),
            extensions,
        }
    }

    /// Clears every field, as BC's `Reset` does, leaving the generator as `new` makes it.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn set_issuer(&mut self, issuer: Name) {
        self.issuer = Some(issuer);
    }

    /// The issuer from a string such as `"CN=My CA,O=Acme"`; `Asn1` when it does not parse.
    pub fn set_issuer_by_str(&mut self, issuer: &str) -> Result<(), X509Error> {
        self.issuer = Some(issuer.parse()?);
        Ok(())
    }

    /// The issuer as the subject of the CA's certificate, so that the names match exactly.
    pub fn set_issuer_by_certificate(&mut self, ca: &X509Certificate) {
        self.issuer = Some(ca.subject().clone());
    }

    pub fn clear_issuer(&mut self) {
        self.issuer = None;
    }

    /// When this CRL was issued, BC's `SetThisUpdate`. Without it, `generate` uses the time it
    /// runs.
    pub fn set_this_update(&mut self, this_update: Time) {
        self.this_update = Some(this_update);
    }

    /// When this CRL was issued, to the second; `Asn1` when it falls outside 1950-9999.
    pub fn set_this_update_by_datetime(
        &mut self,
        this_update: DateTime<Utc>,
    ) -> Result<(), X509Error> {
        self.this_update = Some(Time::try_from(this_update)?);
        Ok(())
    }

    pub fn clear_this_update(&mut self) {
        self.this_update = None;
    }

    /// When the next CRL is due, BC's `SetNextUpdate`. RFC 5280 section 5.1.2.5 requires it of a
    /// conforming CRL, though ASN.1 and BC leave it out when it is not set.
    pub fn set_next_update(&mut self, next_update: Time) {
        self.next_update = Some(NextUpdate::At(next_update));
    }

    /// When the next CRL is due, to the second; `Asn1` when it falls outside 1950-9999.
    pub fn set_next_update_by_datetime(
        &mut self,
        next_update: DateTime<Utc>,
    ) -> Result<(), X509Error> {
        self.next_update = Some(NextUpdate::At(Time::try_from(next_update)?));
        Ok(())
    }

    /// The next CRL is due `after` the this update, such as `TimeDelta::days(7)` or
    /// `TimeDelta::hours(6)`. Worked out when the CRL is generated, from the this update then,
    /// which is the time `generate` runs when it is not set.
    pub fn set_next_update_after(&mut self, after: TimeDelta) {
        self.next_update = Some(NextUpdate::After(after));
    }

    pub fn clear_next_update(&mut self) {
        self.next_update = None;
    }

    /// Lists the certificate with the serial number as revoked on `revocation_date`, with the
    /// reason as its reasonCode extension, not critical as RFC 5280 section 5.3.1 requires; BC's
    /// `AddCrlEntry`. `None` leaves the reason out, which RFC 5280 asks for rather than
    /// `Unspecified`. Entries are listed in the order they are added.
    pub fn add_crl_entry(
        &mut self,
        serial_number: Asn1Integer,
        revocation_date: Time,
        reason: Option<CrlReason>,
    ) -> Result<(), X509Error> {
        let mut entry = RevokedCertificate::new(serial_number, revocation_date);
        if let Some(reason) = reason {
            let extension = Extension::with_value(ExtensionId::CRL_REASONS, false, &reason)?;
            entry = entry.with_extensions(Extensions::new(vec![extension])?);
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Lists the certificate with the serial number as revoked on `revocation_date`, with its own
    /// entry extensions, such as the reasonCode, the invalidityDate or, in an indirect CRL, the
    /// certificateIssuer; BC's `AddCrlEntry` with extensions.
    pub fn add_crl_entry_with_extensions(
        &mut self,
        serial_number: Asn1Integer,
        revocation_date: Time,
        extensions: Extensions,
    ) {
        self.entries.push(
            RevokedCertificate::new(serial_number, revocation_date).with_extensions(extensions),
        );
    }

    /// Adds every entry of another CRL, as they are, extensions included, after those already
    /// added; BC's `AddCrl`. Use it to carry the revocations of the last CRL into the next.
    pub fn add_crl(&mut self, other: &X509Crl) {
        self.entries
            .extend_from_slice(other.certificate_list().revoked_certificates());
    }

    /// Takes out the entries with the serial number, and returns whether there was one.
    pub fn remove_crl_entry(&mut self, serial_number: &Asn1Integer) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|entry| entry.user_certificate() != serial_number);
        self.entries.len() != before
    }

    /// Takes out every entry added.
    pub fn clear_crl_entries(&mut self) {
        self.entries.clear();
    }

    /// `DuplicateExtension` when one with the same OID is already added, as RFC 5280 section 5.2
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

    /// The sequence number of the CRL, not marked critical, as RFC 5280 section 5.2.3 requires of
    /// a conforming CRL; `Asn1` unless it is a non-negative integer of at most 20 bytes.
    pub fn add_crl_number(&mut self, number: impl Into<Asn1Integer>) -> Result<(), X509Error> {
        let value = CrlNumber::new(number)?;
        self.add_extension(Extension::with_value(
            ExtensionId::CRL_NUMBER,
            false,
            &value,
        )?)
    }

    /// The key that signs the CRL, as the subjectKeyIdentifier of the CA's certificate, not marked
    /// critical, as RFC 5280 section 5.2.1 requires of a conforming CRL. `MissingExtension` when
    /// the certificate has none.
    pub fn add_authority_key_identifier(&mut self, ca: &X509Certificate) -> Result<(), X509Error> {
        let mut context = DecodingContext::new(DecodingOptions::default());
        let subject_key_identifier = ca
            .extensions()
            .map(|extensions| extensions.get_subject_key_identifier(&mut context))
            .transpose()?
            .flatten()
            .ok_or(X509Error::MissingExtension("subjectKeyIdentifier"))?;
        let value =
            AuthorityKeyIdentifier::from_key_identifier(subject_key_identifier.key_identifier())?;
        self.add_extension(Extension::with_value(
            ExtensionId::AUTHORITY_KEY_IDENTIFIER,
            false,
            &value,
        )?)
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

    /// Signs the fields into a CRL, as BC's `Generate` does. `MissingField` names a field not
    /// set; without a this update, the time of the call is used, where BC requires one. The signature algorithm of the factory goes into the signed part. The generator is
    /// left as it was.
    pub fn generate(&self, factory: &dyn SignatureFactory) -> Result<X509Crl, X509Error> {
        let issuer = self
            .issuer
            .clone()
            .ok_or(X509Error::MissingField("issuer"))?;
        let this_update = match self.this_update {
            Some(this_update) => this_update,
            None => Time::try_from(Utc::now())?,
        };
        let next_update = match self.next_update {
            None => None,
            Some(NextUpdate::At(next_update)) => Some(next_update),
            Some(NextUpdate::After(after)) => {
                let start: DateTime<Utc> = this_update.into();
                let end = start
                    .checked_add_signed(after)
                    .ok_or(Asn1Error::MalformedValue)?;
                Some(Time::try_from(end)?)
            }
        };
        let mut tbs = TbsCertList::new(
            Version::V2,
            factory.algorithm().clone(),
            issuer,
            this_update,
        )?
        .with_revoked_certificates(self.entries.clone())?;
        if let Some(next_update) = next_update {
            tbs = tbs.with_next_update(next_update);
        }
        if !self.extensions.is_empty() {
            tbs = tbs.with_extensions(Extensions::new(self.extensions.clone())?)?;
        }
        let der = tbs.encode_to_vec(&EncodingOptions::DER)?;

        let mut calculator = factory.create_calculator()?;
        calculator.write_all(&der)?;
        let signature = calculator.result().collect()?;

        let list = CertificateList::new(tbs, Asn1BitString::from_bytes(&signature))?;
        Ok(X509Crl::new(list)?)
    }
}
