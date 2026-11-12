use std::io::{self, Read, Write};

use tc_asn1::{
    Asn1Error, Asn1Integer, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions,
};
use tc_asn1::io::Asn1Reader;
use tc_asn1_x500::Name;
use tc_asn1_x509::{
    alg::AlgorithmIdentifier,
    cert::Time,
    crl::{CertificateList, CrlReason},
    ext::Extensions,
};

use crate::X509Error;
use crate::cert::X509Certificate;
use crate::crl::X509CrlEntry;
use crate::operator::verifier::VerifierFactoryProvider;

/// BC's `X509Crl`: a certificate revocation list as received, with the accessors of its fields
/// and the lookup of its entries. Every method is variable time, for public values only, as a CRL
/// is.
///
#[doc = include_str!("../../docs/X509Crl.md")]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct X509Crl {
    list: CertificateList,
    is_indirect: bool,
}

impl X509Crl {
    /// Wraps a CRL already decoded or built, as BC's constructor does. `Asn1` when its
    /// issuingDistributionPoint extension does not decode.
    pub fn new(list: CertificateList) -> Result<Self, Asn1Error> {
        let is_indirect = match list.extensions() {
            Some(extensions) => {
                let mut context = DecodingContext::new(DecodingOptions::default());
                extensions
                    .get_issuing_distribution_point(&mut context)?
                    .is_some_and(|point| point.indirect_crl())
            }
            None => false,
        };
        Ok(Self { list, is_indirect })
    }

    /// Decodes one BER or DER CRL, keeping the signed octets as received. Trailing bytes are
    /// `TrailingData`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Asn1Error> {
        let (used, list) = CertificateList::decode(bytes, &DecodingOptions::default())?;
        if used != bytes.len() {
            return Err(Asn1Error::TrailingData);
        }
        Self::new(list)
    }

    /// Reads one BER or DER CRL from `input` and nothing past it, so what follows
    /// stays in `input` for the next call; `None` when the input ends before a value
    /// starts. Read it through a `BufReader` for a file or a socket. A value that does
    /// not decode is `io::ErrorKind::InvalidData` carrying the [`Asn1Error`]; input that
    /// ends inside it is `io::ErrorKind::UnexpectedEof`. Variable time, for public
    /// values only.
    pub fn decode_from<R: Read>(input: R) -> io::Result<Option<Self>> {
        let mut reader = Asn1Reader::new(input, DecodingOptions::default());
        reader
            .read_value::<CertificateList>()?
            .map(Self::new)
            .transpose()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// The DER octets, BC's `GetEncoded`. The signed octets are written as received, so that the
    /// signature stays valid.
    pub fn encode(&self) -> Result<Vec<u8>, Asn1Error> {
        self.list.encode_to_vec(&EncodingOptions::DER)
    }

    /// Writes [`encode`](Self::encode) to `out`. An encoding failure is
    /// `io::ErrorKind::InvalidData` carrying the [`Asn1Error`], with nothing written.
    /// Variable time, for public values only.
    pub fn encode_to<W: Write>(&self, out: &mut W) -> std::io::Result<()> {
        let encoding = self
            .encode()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        out.write_all(&encoding)
    }

    /// The ASN.1 structure, BC's `CertificateList`.
    pub fn certificate_list(&self) -> &CertificateList {
        &self.list
    }

    pub fn version(&self) -> tc_asn1_x509::cert::Version {
        self.list.tbs().version()
    }

    pub fn issuer(&self) -> &Name {
        self.list.issuer()
    }

    pub fn this_update(&self) -> Time {
        *self.list.this_update()
    }

    pub fn next_update(&self) -> Option<Time> {
        self.list.next_update().copied()
    }

    /// Whether the CRL lists certificates of issuers other than its own, RFC 5280 section 5.2.5,
    /// BC's `IsIndirect`.
    pub fn is_indirect(&self) -> bool {
        self.is_indirect
    }

    /// The entry with the serial number, BC's `GetRevokedCertificate(BigInteger)`. In an indirect
    /// CRL a serial number is unique only within its issuer, so prefer `revoked_certificate_of`.
    pub fn revoked_certificate(&self, serial_number: &Asn1Integer) -> Option<X509CrlEntry<'_>> {
        let mut issuer = None;
        for entry in self.list.revoked_certificates() {
            issuer = X509CrlEntry::load_certificate_issuer(entry, self.is_indirect, issuer);
            if entry.user_certificate() == serial_number {
                return Some(X509CrlEntry::new(entry, issuer));
            }
        }
        None
    }

    /// The entry of the certificate, matching its issuer as well as its serial number, BC's
    /// `GetRevokedCertificate(X509Certificate)`.
    pub fn revoked_certificate_of(
        &self,
        certificate: &X509Certificate,
    ) -> Option<X509CrlEntry<'_>> {
        let issued_by_crl_issuer = certificate.issuer().equivalent(self.issuer());
        if !self.is_indirect {
            return if issued_by_crl_issuer {
                self.revoked_certificate(certificate.serial_number())
            } else {
                None
            };
        }

        let mut issuer: Option<Name> = None;
        for entry in self.list.revoked_certificates() {
            issuer = X509CrlEntry::load_certificate_issuer(entry, true, issuer);
            if entry.user_certificate() != certificate.serial_number() {
                continue;
            }
            let matches = match &issuer {
                Some(issuer) => certificate.issuer().equivalent(issuer),
                None => issued_by_crl_issuer,
            };
            if matches {
                return Some(X509CrlEntry::new(entry, issuer));
            }
        }
        None
    }

    /// Whether the certificate is listed as revoked, BC's `IsRevoked`: listed under its issuer
    /// and serial number, with any reason but `removeFromCRL`, which a delta CRL gives a
    /// certificate whose hold is lifted. A reason that does not decode counts as revoked. A
    /// CRL of another issuer is `false`; its signature is the caller's to verify with the key
    /// of the issuer. Variable time, for public values only.
    pub fn is_revoked(&self, certificate: &X509Certificate) -> bool {
        self.revoked_certificate_of(certificate).is_some_and(|entry| {
            let mut context = DecodingContext::new(DecodingOptions::default());
            !entry.extensions().is_some_and(|extensions| {
                matches!(
                    extensions.get_crl_reason(&mut context),
                    Ok(Some(CrlReason::RemoveFromCrl))
                )
            })
        })
    }

    /// Every entry, in the order of the list, BC's `GetRevokedCertificates`; empty when there is
    /// none, where BC gives null.
    pub fn revoked_certificates(&self) -> Vec<X509CrlEntry<'_>> {
        let mut issuer = None;
        self.list
            .revoked_certificates()
            .iter()
            .map(|entry| {
                issuer =
                    X509CrlEntry::load_certificate_issuer(entry, self.is_indirect, issuer.take());
                X509CrlEntry::new(entry, issuer.clone())
            })
            .collect()
    }

    pub fn extensions(&self) -> Option<&Extensions> {
        self.list.extensions()
    }

    /// The signed octets, BC's `GetTbsCertList`.
    pub fn tbs_cert_list(&self) -> &[u8] {
        self.list.tbs_raw()
    }

    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        self.list.signature_algorithm()
    }

    /// The signature octets, BC's `GetSignature`.
    pub fn signature(&self) -> &[u8] {
        self.list.signature_value().as_bytes()
    }

    /// Whether the signature verifies with the CRL issuer's key the provider holds, BC's
    /// `IsSignatureValid`. `AlgorithmMismatch` when the algorithm inside the signed part differs
    /// from the outer one.
    pub fn is_signature_valid(
        &self,
        provider: &dyn VerifierFactoryProvider,
    ) -> Result<bool, X509Error> {
        if self.signature_algorithm() != self.list.tbs().signature() {
            return Err(X509Error::AlgorithmMismatch);
        }
        let factory = provider.create_verifier_factory(self.signature_algorithm())?;
        let mut calculator = factory.create_calculator()?;
        calculator.write_all(self.tbs_cert_list())?;
        calculator.result().is_verified(self.signature())
    }

    /// As `is_signature_valid`, with `InvalidSignature` for a signature that does not verify,
    /// BC's `Verify`.
    pub fn verify(&self, provider: &dyn VerifierFactoryProvider) -> Result<(), X509Error> {
        if self.is_signature_valid(provider)? {
            Ok(())
        } else {
            Err(X509Error::InvalidSignature)
        }
    }
}
