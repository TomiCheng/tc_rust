use tc_asn1::{DecodingContext, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_asn1_x509::ext::{AuthorityKeyIdentifier, Extension, ExtensionId, SubjectKeyIdentifier};
use tc_digest::Digest;
use tc_sha::Sha1Digest;

use crate::X509Error;
use crate::cert::X509Certificate;

/// The key identifier of a public key by RFC 5280 section 4.2.1.2, method 1: the SHA-1 of the
/// octets of its subjectPublicKey, the tag, length and unused-bits octet aside. Variable time,
/// for public values only.
pub fn key_identifier_of(public_key: &SubjectPublicKeyInfo) -> [u8; 20] {
    let mut digest = Sha1Digest::new();
    digest.update(public_key.subject_public_key().as_bytes());
    let mut identifier = [0u8; 20];
    digest.do_final(&mut identifier);
    identifier
}

/// The subjectKeyIdentifier extension of a certificate whose public key is `public_key`, its
/// identifier by [`key_identifier_of`]; not critical, as RFC 5280 requires. A CA certificate
/// must carry it. Variable time, for public values only.
///
/// # Examples
///
/// The extension for the public key of a certificate to issue, here that of a CA read from a
/// file, for a generator's `add_extension`:
///
/// ```
/// use tc_x509::cert::X509Certificate;
/// use tc_x509::extension::subject_key_identifier;
///
/// let path = format!("{}/tests/data/crl/ca.der", env!("CARGO_MANIFEST_DIR"));
/// let ca = X509Certificate::decode(&std::fs::read(path)?)?;
/// let extension = subject_key_identifier(ca.subject_public_key_info())?;
/// assert!(!extension.critical());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn subject_key_identifier(public_key: &SubjectPublicKeyInfo) -> Result<Extension, X509Error> {
    let value = SubjectKeyIdentifier::new(key_identifier_of(public_key))?;
    Ok(Extension::new(
        ExtensionId::SUBJECT_KEY_IDENTIFIER,
        false,
        &value.encode_to_vec(&EncodingOptions::DER)?,
    ))
}

/// The authorityKeyIdentifier extension of a certificate `issuer` issues: the subject key
/// identifier of the issuer, or, when it carries none, the identifier of its public key by
/// [`key_identifier_of`]; not critical, as RFC 5280 requires. Every certificate but a
/// self-signed root must carry it. A subjectKeyIdentifier of the issuer that does not decode is
/// `Asn1`. Variable time, for public values only.
///
/// # Examples
///
/// The extension for a certificate the CA of a file issues, for a generator's
/// `add_extension`:
///
/// ```
/// use tc_x509::cert::X509Certificate;
/// use tc_x509::extension::authority_key_identifier;
///
/// let path = format!("{}/tests/data/crl/ca.der", env!("CARGO_MANIFEST_DIR"));
/// let ca = X509Certificate::decode(&std::fs::read(path)?)?;
/// let extension = authority_key_identifier(&ca)?;
/// assert!(!extension.critical());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn authority_key_identifier(issuer: &X509Certificate) -> Result<Extension, X509Error> {
    let mut context = DecodingContext::new(DecodingOptions::default());
    let carried = match issuer.extensions() {
        Some(extensions) => extensions.get_subject_key_identifier(&mut context)?,
        None => None,
    };
    let value = match carried {
        Some(identifier) => AuthorityKeyIdentifier::from_key_identifier(identifier.key_identifier())?,
        None => AuthorityKeyIdentifier::from_key_identifier(&key_identifier_of(
            issuer.subject_public_key_info(),
        ))?,
    };
    Ok(Extension::new(
        ExtensionId::AUTHORITY_KEY_IDENTIFIER,
        false,
        &value.encode_to_vec(&EncodingOptions::DER)?,
    ))
}
