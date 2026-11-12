use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::sync::OnceLock;

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
#[derive(Clone)]
pub struct X509Crl {
    list: CertificateList,
    is_indirect: bool,
    index: OnceLock<EntryIndex>,
}

// The entries by serial number, built on the first lookup so that a lookup costs one hash
// rather than a pass over every entry
#[derive(Clone)]
struct EntryIndex {
    // The positions of the entries with each serial number, in list order
    by_serial: HashMap<Vec<u8>, Vec<usize>>,
    // For an indirect CRL, the issuer each entry falls under, as a position in `issuers`, which
    // holds each run of the same issuer once
    issuer_of: Vec<usize>,
    issuers: Vec<Option<Name>>,
}

impl EntryIndex {
    fn build(list: &CertificateList, is_indirect: bool) -> Self {
        let mut by_serial: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
        let mut issuer_of = Vec::new();
        let mut issuers: Vec<Option<Name>> = Vec::new();
        let mut issuer = None;
        for (position, entry) in list.revoked_certificates().iter().enumerate() {
            by_serial
                .entry(entry.user_certificate().as_bytes().to_vec())
                .or_default()
                .push(position);
            if is_indirect {
                issuer = X509CrlEntry::load_certificate_issuer(entry, true, issuer.take());
                if issuers.last() != Some(&issuer) {
                    issuers.push(issuer.clone());
                }
                issuer_of.push(issuers.len() - 1);
            }
        }
        Self {
            by_serial,
            issuer_of,
            issuers,
        }
    }

    fn positions(&self, serial_number: &Asn1Integer) -> &[usize] {
        self.by_serial
            .get(serial_number.as_bytes())
            .map_or(&[], Vec::as_slice)
    }

    fn issuer_at(&self, position: usize) -> Option<Name> {
        self.issuer_of
            .get(position)
            .and_then(|&run| self.issuers[run].clone())
    }
}

// The index is derived from the list, so it takes no part in comparing or hashing
impl PartialEq for X509Crl {
    fn eq(&self, other: &Self) -> bool {
        self.list == other.list && self.is_indirect == other.is_indirect
    }
}

impl Eq for X509Crl {}

impl Hash for X509Crl {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.list.hash(state);
        self.is_indirect.hash(state);
    }
}

impl fmt::Debug for X509Crl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509Crl")
            .field("list", &self.list)
            .field("is_indirect", &self.is_indirect)
            .finish_non_exhaustive()
    }
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
        Ok(Self {
            list,
            is_indirect,
            index: OnceLock::new(),
        })
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
    /// The first lookup indexes the entries by serial number, so later ones cost a hash.
    pub fn revoked_certificate(&self, serial_number: &Asn1Integer) -> Option<X509CrlEntry<'_>> {
        let index = self.index();
        let &position = index.positions(serial_number).first()?;
        Some(self.entry_at(index, position))
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

        let index = self.index();
        index
            .positions(certificate.serial_number())
            .iter()
            .map(|&position| self.entry_at(index, position))
            .find(|entry| match entry.certificate_issuer() {
                Some(issuer) => certificate.issuer().equivalent(issuer),
                None => issued_by_crl_issuer,
            })
    }

    fn index(&self) -> &EntryIndex {
        self.index
            .get_or_init(|| EntryIndex::build(&self.list, self.is_indirect))
    }

    fn entry_at(&self, index: &EntryIndex, position: usize) -> X509CrlEntry<'_> {
        X509CrlEntry::new(
            &self.list.revoked_certificates()[position],
            index.issuer_at(position),
        )
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
