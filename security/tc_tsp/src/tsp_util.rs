use tc_asn1::{DecodingContext, DecodingOptions};
use tc_asn1_x509::cert::Version;
use tc_asn1_x509::ext::{ExtensionId, KeyPurposeId};
use tc_x509::cert::X509Certificate;

use crate::TspError;

// BC 的 TspUtil.ValidateCertificate：TSA 的憑證要是 v3，帶 critical 的 extendedKeyUsage，而且只有
// id-kp-timeStamping，同 RFC 3161 §2.3
pub fn validate_certificate(certificate: &X509Certificate) -> Result<(), TspError> {
    if certificate.version() != Version::V3 {
        return Err(TspError::Validation(
            "certificate must have an ExtendedKeyUsage extension",
        ));
    }
    let extensions = certificate.extensions().ok_or(TspError::Validation(
        "certificate must have an ExtendedKeyUsage extension",
    ))?;
    let extension = extensions
        .get(ExtensionId::EXT_KEY_USAGE)
        .ok_or(TspError::Validation(
            "certificate must have an ExtendedKeyUsage extension",
        ))?;
    if !extension.critical() {
        return Err(TspError::Validation(
            "certificate must have an ExtendedKeyUsage extension marked as critical",
        ));
    }
    let mut context = DecodingContext::new(DecodingOptions::default());
    let usage = extensions
        .get_extended_key_usage(&mut context)
        .map_err(|_| TspError::Validation("cannot process ExtendedKeyUsage extension"))?
        .ok_or(TspError::Validation(
            "certificate must have an ExtendedKeyUsage extension",
        ))?;
    let purposes = usage.purposes();
    if purposes.len() != 1 || KeyPurposeId::TIME_STAMPING != purposes[0] {
        return Err(TspError::Validation(
            "ExtendedKeyUsage not solely time stamping",
        ));
    }
    Ok(())
}
