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

use crate::{BasicConstraints, ExtendedKeyUsage, Extension, ExtensionId, KeyUsage};

/// A non-empty list of extensions with unique OIDs.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions, EncodingType};
/// use tc_asn1_x509::{BasicConstraints, Extension, ExtensionId, Extensions, KeyUsage};
///
/// // A CA certificate's extensions: both critical, as RFC 5280 recommends.
/// let mut extensions = Extensions::single(Extension::with_value(
///     ExtensionId::BASIC_CONSTRAINTS,
///     true,
///     &BasicConstraints::ca(None),
/// )?);
/// extensions.set_key_usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN, true)?;
/// let der = extensions.encode_to_vec(&EncodingOptions::new(EncodingType::Der))?;
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

    /// A list of one; grow it with [`set`](Self::set).
    pub fn single(extension: Extension) -> Self {
        Self {
            extensions: Asn1SequenceOf::new(Vec::from([extension])),
        }
    }

    /// Adds the extension, replacing the one with the same OID in place if
    /// there is one, appending otherwise.
    pub fn set(&mut self, extension: Extension) {
        let mut extensions =
            core::mem::replace(&mut self.extensions, Asn1SequenceOf::new(Vec::new()))
                .into_elements();
        match extensions
            .iter_mut()
            .find(|existing| existing.extn_id() == extension.extn_id())
        {
            Some(existing) => *existing = extension,
            None => extensions.push(extension),
        }
        self.extensions = Asn1SequenceOf::new(extensions);
    }

    /// [`set`](Self::set) with the value DER-encoded, as
    /// [`Extension::with_value`] does.
    pub fn set_value(
        &mut self,
        extn_id: impl Into<Asn1Oid>,
        critical: bool,
        value: &impl Encode,
    ) -> Result<(), Asn1Error> {
        self.set(Extension::with_value(extn_id, critical, value)?);
        Ok(())
    }

    /// [`set_value`](Self::set_value) for keyUsage; RFC 5280 says it SHOULD
    /// be critical.
    pub fn set_key_usage(&mut self, usage: KeyUsage, critical: bool) -> Result<(), Asn1Error> {
        self.set_value(ExtensionId::KEY_USAGE, critical, &usage)
    }

    /// [`set_value`](Self::set_value) for basicConstraints; RFC 5280 says it
    /// MUST be critical in a CA certificate.
    pub fn set_basic_constraints(
        &mut self,
        constraints: BasicConstraints,
        critical: bool,
    ) -> Result<(), Asn1Error> {
        self.set_value(ExtensionId::BASIC_CONSTRAINTS, critical, &constraints)
    }

    /// [`set_value`](Self::set_value) for extKeyUsage.
    pub fn set_extended_key_usage(
        &mut self,
        usage: &ExtendedKeyUsage,
        critical: bool,
    ) -> Result<(), Asn1Error> {
        self.set_value(ExtensionId::EXT_KEY_USAGE, critical, usage)
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

    use tc_asn1::{
        Asn1Error, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions, EncodingType,
    };

    use super::Extensions;
    use crate::{
        BasicConstraints, ExtendedKeyUsage, Extension, ExtensionId, KeyPurposeId, KeyUsage,
    };

    fn der() -> EncodingOptions {
        EncodingOptions::new(EncodingType::Der)
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
    fn set_appends_new_oids_and_replaces_existing_ones_in_place() {
        let mut extensions = Extensions::single(
            Extension::with_value(
                ExtensionId::BASIC_CONSTRAINTS,
                true,
                &BasicConstraints::ca(Some(0)),
            )
            .unwrap(),
        );
        extensions
            .set_key_usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN, true)
            .unwrap();
        assert_eq!(extensions, ca_extensions());
        assert_eq!(extensions.encode_to_vec(&der()).unwrap(), CA);

        // replacing keeps the position and the count
        extensions
            .set_basic_constraints(BasicConstraints::ca(None), true)
            .unwrap();
        assert_eq!(extensions.extensions().len(), 2);
        assert_eq!(
            extensions.extensions()[0].extn_id(),
            &ExtensionId::BASIC_CONSTRAINTS.oid()
        );
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_basic_constraints(&mut context).unwrap(),
            Some(BasicConstraints::ca(None))
        );

        let eku = ExtendedKeyUsage::new(Vec::from([KeyPurposeId::SERVER_AUTH.oid()])).unwrap();
        extensions.set_extended_key_usage(&eku, false).unwrap();
        assert_eq!(extensions.extensions().len(), 3);
        assert!(!extensions.extensions()[2].critical());
        assert_eq!(
            extensions.get_extended_key_usage(&mut context).unwrap(),
            Some(eku)
        );
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
