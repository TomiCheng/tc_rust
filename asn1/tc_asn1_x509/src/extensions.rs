//! RFC 5280 §4.1.2.9 `Extensions`.
//!
//! ```text
//! Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
//! ```
//!
//! The extension list of a certificate or CRL, in wire order. It is never
//! empty and, per RFC 5280 §4.2, never holds two extensions with the same
//! OID; both are enforced. Whether an unrecognized critical extension makes
//! the certificate unusable is the validator's call, made with [`get`] and
//! [`Extension::critical`].
//!
//! [`get`]: Extensions::get

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1SequenceOf, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

use crate::{
    BasicConstraints, ExtendedKeyUsage, Extension, ExtensionId, GeneralNames, KeyUsage,
    SubjectKeyIdentifier,
};

/// A non-empty list of extensions with unique OIDs.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{BasicConstraints, Extension, ExtensionId, Extensions, KeyUsage};
///
/// // A CA certificate's extensions: both critical, as RFC 5280 recommends.
/// let extensions = Extensions::new(vec![
///     Extension::with_value(ExtensionId::BASIC_CONSTRAINTS, true, &BasicConstraints::ca(None))?,
///     Extension::with_value(ExtensionId::KEY_USAGE, true, &(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN))?,
/// ])?;
///
/// // The known extensions have typed accessors ...
/// let mut context = DecodingContext::new(DecodingOptions::default());
/// let usage = extensions.get_key_usage(&mut context)?.unwrap();
/// assert!(usage.contains(KeyUsage::KEY_CERT_SIGN));
/// assert!(extensions.get_extended_key_usage(&mut context)?.is_none());
///
/// // ... and anything can be looked up by OID.
/// let raw = extensions.get(ExtensionId::BASIC_CONSTRAINTS).unwrap();
/// assert!(raw.critical());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Extensions {
    extensions: Asn1SequenceOf<Extension>,
}

impl Extensions {
    /// An empty list or a repeated OID is `MalformedValue`.
    pub fn new(extensions: Vec<Extension>) -> Result<Self, Asn1Error> {
        Self::check(&extensions)?;
        Ok(Self {
            extensions: Asn1SequenceOf::new(extensions),
        })
    }

    fn check(extensions: &[Extension]) -> Result<(), Asn1Error> {
        if extensions.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        for (i, extension) in extensions.iter().enumerate() {
            if extensions[..i]
                .iter()
                .any(|earlier| earlier.extn_id() == extension.extn_id())
            {
                return Err(Asn1Error::MalformedValue);
            }
        }
        Ok(())
    }

    /// The extensions in wire order, never empty.
    pub fn extensions(&self) -> &[Extension] {
        self.extensions.elements()
    }

    /// The extension with this OID, if present; takes a `NamedOid` constant
    /// such as [`ExtensionId::KEY_USAGE`](crate::ExtensionId::KEY_USAGE) or an `Asn1Oid`.
    /// Variable time; for public values.
    pub fn get(&self, extn_id: impl PartialEq<Asn1Oid>) -> Option<&Extension> {
        self.extensions()
            .iter()
            .find(|extension| extn_id == *extension.extn_id())
    }

    /// [`get`](Self::get) followed by [`Extension::extn_value_as`]: `None`
    /// when the extension is absent, an error when it is present but its
    /// value does not decode as `T`.
    pub fn get_as<T: DecodeInner>(
        &self,
        extn_id: impl PartialEq<Asn1Oid>,
        context: &mut DecodingContext,
    ) -> Result<Option<T>, Asn1Error> {
        self.get(extn_id)
            .map(|extension| extension.extn_value_as(context))
            .transpose()
    }

    /// [`get_as`](Self::get_as) for the keyUsage extension.
    pub fn get_key_usage(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<KeyUsage>, Asn1Error> {
        self.get_as(ExtensionId::KEY_USAGE, context)
    }

    /// [`get_as`](Self::get_as) for the basicConstraints extension.
    pub fn get_basic_constraints(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<BasicConstraints>, Asn1Error> {
        self.get_as(ExtensionId::BASIC_CONSTRAINTS, context)
    }

    /// [`get_as`](Self::get_as) for the extKeyUsage extension.
    pub fn get_extended_key_usage(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<ExtendedKeyUsage>, Asn1Error> {
        self.get_as(ExtensionId::EXT_KEY_USAGE, context)
    }

    /// [`get_as`](Self::get_as) for the subjectKeyIdentifier extension.
    pub fn get_subject_key_identifier(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<SubjectKeyIdentifier>, Asn1Error> {
        self.get_as(ExtensionId::SUBJECT_KEY_IDENTIFIER, context)
    }

    /// [`get_as`](Self::get_as) for the subjectAltName extension, whose
    /// value is a plain `GeneralNames`.
    pub fn get_subject_alt_name(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<GeneralNames>, Asn1Error> {
        self.get_as(ExtensionId::SUBJECT_ALT_NAME, context)
    }

    /// [`get_as`](Self::get_as) for the issuerAltName extension.
    pub fn get_issuer_alt_name(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<GeneralNames>, Asn1Error> {
        self.get_as(ExtensionId::ISSUER_ALT_NAME, context)
    }
}

impl DecodeInner for Extensions {
    /// An empty SEQUENCE or a repeated OID is `MalformedValue`. Variable
    /// time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, extensions) = Asn1SequenceOf::<Extension>::decode_inner(buff, context)?;
        Self::check(extensions.elements())?;
        Ok((used, Self { extensions }))
    }
}

impl Decode for Extensions {}

impl Tagged for Extensions {
    const TAG: &'static [u8] = Asn1SequenceOf::<Extension>::TAG;
}

impl EncodeContent for Extensions {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.extensions.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.extensions.encode_content(rules, out)
    }
}

impl EncodeTagged for Extensions {}

impl Encode for Extensions {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use tc_asn1::{Asn1Error, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions};

    use super::Extensions;
    use crate::{
        BasicConstraints, ExtendedKeyUsage, Extension, ExtensionId, GeneralName, GeneralNames,
        KeyUsage,
    };

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn ca_extensions() -> Extensions {
        Extensions::new(Vec::from([
            Extension::new(
                ExtensionId::BASIC_CONSTRAINTS,
                true,
                &BasicConstraints::ca(Some(0)).encode_to_vec(&der()).unwrap(),
            ),
            Extension::new(
                ExtensionId::KEY_USAGE,
                true,
                &(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
                    .encode_to_vec(&der())
                    .unwrap(),
            ),
        ]))
        .unwrap()
    }

    /// basicConstraints { cA, pathLen 0 } critical, keyUsage { keyCertSign, cRLSign } critical.
    const CA: &[u8] = b"\x30\x24\
        \x30\x12\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x08\x30\x06\x01\x01\xff\x02\x01\x00\
        \x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x06";

    #[test]
    fn extensions_round_trip_in_order() {
        let extensions = ca_extensions();
        assert_eq!(extensions.encode_to_vec(&der()).unwrap(), CA);
        let (used, decoded) = Extensions::decode(CA, &options()).unwrap();
        assert_eq!((used, &decoded), (CA.len(), &extensions));
        assert_eq!(
            decoded.extensions()[0].extn_id(),
            &ExtensionId::BASIC_CONSTRAINTS.oid()
        );
        assert_eq!(
            decoded.extensions()[1].extn_id(),
            &ExtensionId::KEY_USAGE.oid()
        );
    }

    #[test]
    fn lookup_by_oid_finds_decodes_or_says_absent() {
        let (_, extensions) = Extensions::decode(CA, &options()).unwrap();
        let mut context = DecodingContext::new(options());
        assert!(extensions.get(ExtensionId::KEY_USAGE).unwrap().critical());
        assert!(extensions.get(ExtensionId::EXT_KEY_USAGE).is_none());
        assert!(
            extensions
                .get("2.5.29.15".parse::<tc_asn1::Asn1Oid>().unwrap())
                .is_some()
        );

        let usage: KeyUsage = extensions
            .get_as(ExtensionId::KEY_USAGE, &mut context)
            .unwrap()
            .unwrap();
        assert_eq!(usage, KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN);
        let bc: BasicConstraints = extensions
            .get_as(ExtensionId::BASIC_CONSTRAINTS, &mut context)
            .unwrap()
            .unwrap();
        assert_eq!(bc.path_len_constraint(), Some(0));
        assert!(
            extensions
                .get_as::<ExtendedKeyUsage>(ExtensionId::EXT_KEY_USAGE, &mut context)
                .unwrap()
                .is_none()
        );
        // present, but the value is not what was asked for
        assert!(
            extensions
                .get_as::<KeyUsage>(ExtensionId::BASIC_CONSTRAINTS, &mut context)
                .is_err()
        );
    }

    #[test]
    fn the_typed_accessors_return_the_present_extensions_and_none_for_absent_ones() {
        let (_, extensions) = Extensions::decode(CA, &options()).unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_key_usage(&mut context).unwrap(),
            Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
        );
        assert_eq!(
            extensions.get_basic_constraints(&mut context).unwrap(),
            Some(BasicConstraints::ca(Some(0)))
        );
        assert_eq!(
            extensions.get_extended_key_usage(&mut context).unwrap(),
            None
        );
    }

    #[test]
    fn the_alt_name_accessors_return_general_names() {
        let san = GeneralNames::new(Vec::from([
            GeneralName::dns_name("x.tw").unwrap(),
            GeneralName::rfc822_name("a@x.tw").unwrap(),
        ]))
        .unwrap();
        let extensions = Extensions::new(Vec::from([Extension::with_value(
            ExtensionId::SUBJECT_ALT_NAME,
            false,
            &san,
        )
        .unwrap()]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_subject_alt_name(&mut context).unwrap(),
            Some(san)
        );
        assert_eq!(extensions.get_issuer_alt_name(&mut context).unwrap(), None);
    }

    #[test]
    fn an_empty_list_and_a_repeated_oid_are_rejected_when_built_or_decoded() {
        assert!(matches!(
            Extensions::new(Vec::new()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            Extensions::decode(b"\x30\x00", &options()),
            Err(Asn1Error::MalformedValue)
        ));
        let usage = Extension::new(
            ExtensionId::KEY_USAGE,
            false,
            &KeyUsage::DIGITAL_SIGNATURE.encode_to_vec(&der()).unwrap(),
        );
        assert!(matches!(
            Extensions::new(Vec::from([usage.clone(), usage.clone()])),
            Err(Asn1Error::MalformedValue)
        ));
        let mut twice: Vec<u8> = CA.to_vec();
        twice.extend_from_slice(&CA[22..]); // the keyUsage extension again
        twice[1] += 16;
        assert!(matches!(
            Extensions::decode(&twice, &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn anything_but_extensions_in_a_sequence_is_rejected() {
        let mut as_set: Vec<u8> = CA.to_vec();
        as_set[0] = 0x31;
        assert!(matches!(
            Extensions::decode(&as_set, &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            Extensions::decode(b"\x30\x03\x02\x01\x01", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
