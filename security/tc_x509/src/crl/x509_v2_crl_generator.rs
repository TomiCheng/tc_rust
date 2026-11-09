use std::io::Write;

use chrono::{DateTime, Utc};
use tc_asn1::{Asn1BitString, Asn1Integer, Encode, EncodingOptions};
use tc_asn1_x500::Name;
use tc_asn1_x509::{
    cert::{Time, Version},
    crl::{CertificateList, CrlReason, RevokedCertificate, TbsCertList},
    ext::{Extension, ExtensionId, Extensions},
};

use crate::X509Error;
use crate::crl::X509Crl;
use crate::operator::signer::SignatureFactory;

/// BC's `X509V2CrlGenerator`: the fields of a version 2 CRL to be signed. A missing field is
/// reported when the CRL is generated. Every method is variable time, for public values only.
///
#[doc = include_str!("../../docs/X509V2CrlGenerator.md")]
#[derive(Clone, Debug, Default)]
pub struct X509V2CrlGenerator {
    issuer: Option<Name>,
    this_update: Option<Time>,
    entries: Vec<RevokedCertificate>,
}

impl X509V2CrlGenerator {
    pub fn new() -> Self {
        Self::default()
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

    /// When this CRL was issued, BC's `SetThisUpdate`.
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

    /// Signs the fields into a CRL, as BC's `Generate` does. `MissingField` names a field not
    /// set. The signature algorithm of the factory goes into the signed part. The generator is
    /// left as it was.
    pub fn generate(&self, factory: &dyn SignatureFactory) -> Result<X509Crl, X509Error> {
        let issuer = self
            .issuer
            .clone()
            .ok_or(X509Error::MissingField("issuer"))?;
        let this_update = self
            .this_update
            .ok_or(X509Error::MissingField("this_update"))?;
        let tbs = TbsCertList::new(
            Version::V2,
            factory.algorithm().clone(),
            issuer,
            this_update,
        )?
        .with_revoked_certificates(self.entries.clone())?;
        let der = tbs.encode_to_vec(&EncodingOptions::DER)?;

        let mut calculator = factory.create_calculator()?;
        calculator.write_all(&der)?;
        let signature = calculator.result().collect()?;

        let list = CertificateList::new(tbs, Asn1BitString::from_bytes(&signature))?;
        Ok(X509Crl::new(list)?)
    }
}
