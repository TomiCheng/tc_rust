use alloc::vec::Vec;

use crate::universal::*;
use crate::{
    Asn1Any, Asn1Constructed, Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions,
};

mod dump;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Asn1Object {
    Boolean(Asn1Boolean),
    Integer(Asn1Integer),
    BitString(Asn1BitString),
    OctetString(Asn1OctetString),
    Null(Asn1Null),
    Oid(Asn1Oid),
    Real(Asn1Real),
    Enumerated(Asn1Enumerated),
    Utf8String(Asn1Utf8String),
    RelativeOid(Asn1RelativeOid),
    Time(Asn1Time),
    NumericString(Asn1NumericString),
    PrintableString(Asn1PrintableString),
    Ia5String(Asn1Ia5String),
    UtcTime(Asn1UtcTime),
    GeneralizedTime(Asn1GeneralizedTime),
    VisibleString(Asn1VisibleString),
    UniversalString(Asn1UniversalString),
    BmpString(Asn1BmpString),
    Date(Asn1Date),
    TimeOfDay(Asn1TimeOfDay),
    DateTime(Asn1DateTime),
    Duration(Asn1Duration),
    OidIri(Asn1OidIri),
    RelativeOidIri(Asn1RelativeOidIri),
    /// A universal SEQUENCE (30).
    SequenceOf(Asn1SequenceOf<Asn1Object>),
    /// A universal SET (31): sorted under CER and DER like a SET OF.
    SetOf(Asn1SetOf<Asn1Object>),
    Constructed(Asn1Constructed<Asn1Object>),
    Unknown(Asn1Any),
}

/// `Asn1Object::from(value)` for every variant, so mixed elements can be
/// written as `vec![oid.into(), Asn1Null.into()]`.
macro_rules! from_variant {
    ($($variant:ident: $ty:ty),* $(,)?) => {$(
        impl From<$ty> for Asn1Object {
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        }
    )*};
}
from_variant! {
    Boolean: Asn1Boolean,
    Integer: Asn1Integer,
    BitString: Asn1BitString,
    OctetString: Asn1OctetString,
    Null: Asn1Null,
    Oid: Asn1Oid,
    Real: Asn1Real,
    Enumerated: Asn1Enumerated,
    Utf8String: Asn1Utf8String,
    RelativeOid: Asn1RelativeOid,
    Time: Asn1Time,
    NumericString: Asn1NumericString,
    PrintableString: Asn1PrintableString,
    Ia5String: Asn1Ia5String,
    UtcTime: Asn1UtcTime,
    GeneralizedTime: Asn1GeneralizedTime,
    VisibleString: Asn1VisibleString,
    UniversalString: Asn1UniversalString,
    BmpString: Asn1BmpString,
    Date: Asn1Date,
    TimeOfDay: Asn1TimeOfDay,
    DateTime: Asn1DateTime,
    Duration: Asn1Duration,
    OidIri: Asn1OidIri,
    RelativeOidIri: Asn1RelativeOidIri,
    SequenceOf: Asn1SequenceOf<Asn1Object>,
    SetOf: Asn1SetOf<Asn1Object>,
    Constructed: Asn1Constructed<Asn1Object>,
    Unknown: Asn1Any,
}

impl Asn1Object {
    /// A SEQUENCE node; fixes the element type so `vec![a.into(), b.into()]` infers.
    pub fn sequence(elements: Vec<Asn1Object>) -> Self {
        Self::SequenceOf(Asn1SequenceOf::new(elements))
    }

    /// A SET node, sorted on CER and DER output.
    pub fn set(members: Vec<Asn1Object>) -> Self {
        Self::SetOf(Asn1SetOf::new(members))
    }

    /// Interprets one primitive element by its universal tag; anything else is
    /// kept as `Unknown`. Variable time: branches only on the identifier.
    fn primitive(
        tag: &[u8],
        value: &[u8],
        context: &mut DecodingContext,
    ) -> Result<Self, Asn1Error> {
        Ok(match tag {
            t if t == tag::BOOLEAN => Self::Boolean(Asn1Boolean::decode_content(value, context)?),
            t if t == tag::INTEGER => Self::Integer(Asn1Integer::decode_content(value, context)?),
            t if t == tag::BIT_STRING => {
                Self::BitString(Asn1BitString::decode_content(value, context)?)
            }
            t if t == tag::OCTET_STRING => {
                Self::OctetString(Asn1OctetString::decode_content(value, context)?)
            }
            t if t == tag::NULL => Self::Null(Asn1Null::decode_content(value, context)?),
            t if t == tag::OBJECT_IDENTIFIER => Self::Oid(Asn1Oid::decode_content(value, context)?),
            t if t == tag::REAL => Self::Real(Asn1Real::decode_content(value, context)?),
            t if t == tag::ENUMERATED => {
                Self::Enumerated(Asn1Enumerated::decode_content(value, context)?)
            }
            t if t == tag::UTF8_STRING => {
                Self::Utf8String(Asn1Utf8String::decode_content(value, context)?)
            }
            t if t == tag::RELATIVE_OID => {
                Self::RelativeOid(Asn1RelativeOid::decode_content(value, context)?)
            }
            t if t == tag::TIME => Self::Time(Asn1Time::decode_content(value, context)?),
            t if t == tag::NUMERIC_STRING => {
                Self::NumericString(Asn1NumericString::decode_content(value, context)?)
            }
            t if t == tag::PRINTABLE_STRING => {
                Self::PrintableString(Asn1PrintableString::decode_content(value, context)?)
            }
            t if t == tag::IA5_STRING => {
                Self::Ia5String(Asn1Ia5String::decode_content(value, context)?)
            }
            t if t == tag::UTC_TIME => Self::UtcTime(Asn1UtcTime::decode_content(value, context)?),
            t if t == tag::GENERALIZED_TIME => {
                Self::GeneralizedTime(Asn1GeneralizedTime::decode_content(value, context)?)
            }
            t if t == tag::VISIBLE_STRING => {
                Self::VisibleString(Asn1VisibleString::decode_content(value, context)?)
            }
            t if t == tag::UNIVERSAL_STRING => {
                Self::UniversalString(Asn1UniversalString::decode_content(value, context)?)
            }
            t if t == tag::BMP_STRING => {
                Self::BmpString(Asn1BmpString::decode_content(value, context)?)
            }
            t if t == tag::DATE => Self::Date(Asn1Date::decode_content(value, context)?),
            t if t == tag::TIME_OF_DAY => {
                Self::TimeOfDay(Asn1TimeOfDay::decode_content(value, context)?)
            }
            t if t == tag::DATE_TIME => {
                Self::DateTime(Asn1DateTime::decode_content(value, context)?)
            }
            t if t == tag::DURATION => {
                Self::Duration(Asn1Duration::decode_content(value, context)?)
            }
            t if t == tag::OID_IRI => Self::OidIri(Asn1OidIri::decode_content(value, context)?),
            t if t == tag::RELATIVE_OID_IRI => {
                Self::RelativeOidIri(Asn1RelativeOidIri::decode_content(value, context)?)
            }
            _ => return Ok(Self::Unknown(Asn1Any::primitive(tag, value))),
        })
    }
}

impl DecodeInner for Asn1Object {
    /// Constructed elements become [`Self::Constructed`] whatever their tag;
    /// primitive ones are interpreted by universal tag or kept as [`Self::Unknown`].
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        if element.tag() == tag::SEQUENCE {
            let (used, inner) = Asn1SequenceOf::decode_inner(element.raw(), context)?;
            return Ok((used, Self::SequenceOf(inner)));
        }
        if element.tag() == tag::SET {
            let (used, inner) = Asn1SetOf::decode_inner(element.raw(), context)?;
            return Ok((used, Self::SetOf(inner)));
        }
        if element.is_constructed() {
            let (used, inner) = Asn1Constructed::decode_inner(element.raw(), context)?;
            return Ok((used, Self::Constructed(inner)));
        }
        let value = Self::primitive(element.tag(), element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1Object {}

impl EncodeContent for Asn1Object {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Boolean(inner) => inner.content_len(rules),
            Self::Integer(inner) => inner.content_len(rules),
            Self::BitString(inner) => inner.content_len(rules),
            Self::OctetString(inner) => inner.content_len(rules),
            Self::Null(inner) => inner.content_len(rules),
            Self::Oid(inner) => inner.content_len(rules),
            Self::Real(inner) => inner.content_len(rules),
            Self::Enumerated(inner) => inner.content_len(rules),
            Self::Utf8String(inner) => inner.content_len(rules),
            Self::RelativeOid(inner) => inner.content_len(rules),
            Self::Time(inner) => inner.content_len(rules),
            Self::NumericString(inner) => inner.content_len(rules),
            Self::PrintableString(inner) => inner.content_len(rules),
            Self::Ia5String(inner) => inner.content_len(rules),
            Self::UtcTime(inner) => inner.content_len(rules),
            Self::GeneralizedTime(inner) => inner.content_len(rules),
            Self::VisibleString(inner) => inner.content_len(rules),
            Self::UniversalString(inner) => inner.content_len(rules),
            Self::BmpString(inner) => inner.content_len(rules),
            Self::Date(inner) => inner.content_len(rules),
            Self::TimeOfDay(inner) => inner.content_len(rules),
            Self::DateTime(inner) => inner.content_len(rules),
            Self::Duration(inner) => inner.content_len(rules),
            Self::OidIri(inner) => inner.content_len(rules),
            Self::RelativeOidIri(inner) => inner.content_len(rules),
            Self::SequenceOf(inner) => inner.content_len(rules),
            Self::SetOf(inner) => inner.content_len(rules),
            Self::Constructed(inner) => inner.content_len(rules),
            Self::Unknown(inner) => inner.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Boolean(inner) => inner.encode_content(rules, out),
            Self::Integer(inner) => inner.encode_content(rules, out),
            Self::BitString(inner) => inner.encode_content(rules, out),
            Self::OctetString(inner) => inner.encode_content(rules, out),
            Self::Null(inner) => inner.encode_content(rules, out),
            Self::Oid(inner) => inner.encode_content(rules, out),
            Self::Real(inner) => inner.encode_content(rules, out),
            Self::Enumerated(inner) => inner.encode_content(rules, out),
            Self::Utf8String(inner) => inner.encode_content(rules, out),
            Self::RelativeOid(inner) => inner.encode_content(rules, out),
            Self::Time(inner) => inner.encode_content(rules, out),
            Self::NumericString(inner) => inner.encode_content(rules, out),
            Self::PrintableString(inner) => inner.encode_content(rules, out),
            Self::Ia5String(inner) => inner.encode_content(rules, out),
            Self::UtcTime(inner) => inner.encode_content(rules, out),
            Self::GeneralizedTime(inner) => inner.encode_content(rules, out),
            Self::VisibleString(inner) => inner.encode_content(rules, out),
            Self::UniversalString(inner) => inner.encode_content(rules, out),
            Self::BmpString(inner) => inner.encode_content(rules, out),
            Self::Date(inner) => inner.encode_content(rules, out),
            Self::TimeOfDay(inner) => inner.encode_content(rules, out),
            Self::DateTime(inner) => inner.encode_content(rules, out),
            Self::Duration(inner) => inner.encode_content(rules, out),
            Self::OidIri(inner) => inner.encode_content(rules, out),
            Self::RelativeOidIri(inner) => inner.encode_content(rules, out),
            Self::SequenceOf(inner) => inner.encode_content(rules, out),
            Self::SetOf(inner) => inner.encode_content(rules, out),
            Self::Constructed(inner) => inner.encode_content(rules, out),
            Self::Unknown(inner) => inner.encode_content(rules, out),
        }
    }
}

/// Each variant writes its own header, so IMPLICIT re-tagging goes to the leaf.
impl EncodeTagged for Asn1Object {
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        match self {
            Self::Boolean(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Integer(inner) => inner.encoded_len_tagged(tag, rules),
            Self::BitString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::OctetString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Null(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Oid(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Real(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Enumerated(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Utf8String(inner) => inner.encoded_len_tagged(tag, rules),
            Self::RelativeOid(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Time(inner) => inner.encoded_len_tagged(tag, rules),
            Self::NumericString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::PrintableString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Ia5String(inner) => inner.encoded_len_tagged(tag, rules),
            Self::UtcTime(inner) => inner.encoded_len_tagged(tag, rules),
            Self::GeneralizedTime(inner) => inner.encoded_len_tagged(tag, rules),
            Self::VisibleString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::UniversalString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::BmpString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Date(inner) => inner.encoded_len_tagged(tag, rules),
            Self::TimeOfDay(inner) => inner.encoded_len_tagged(tag, rules),
            Self::DateTime(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Duration(inner) => inner.encoded_len_tagged(tag, rules),
            Self::OidIri(inner) => inner.encoded_len_tagged(tag, rules),
            Self::RelativeOidIri(inner) => inner.encoded_len_tagged(tag, rules),
            Self::SequenceOf(inner) => inner.encoded_len_tagged(tag, rules),
            Self::SetOf(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Constructed(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Unknown(inner) => inner.encoded_len_tagged(tag, rules),
        }
    }

    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        match self {
            Self::Boolean(inner) => inner.encode_tagged(tag, rules, out),
            Self::Integer(inner) => inner.encode_tagged(tag, rules, out),
            Self::BitString(inner) => inner.encode_tagged(tag, rules, out),
            Self::OctetString(inner) => inner.encode_tagged(tag, rules, out),
            Self::Null(inner) => inner.encode_tagged(tag, rules, out),
            Self::Oid(inner) => inner.encode_tagged(tag, rules, out),
            Self::Real(inner) => inner.encode_tagged(tag, rules, out),
            Self::Enumerated(inner) => inner.encode_tagged(tag, rules, out),
            Self::Utf8String(inner) => inner.encode_tagged(tag, rules, out),
            Self::RelativeOid(inner) => inner.encode_tagged(tag, rules, out),
            Self::Time(inner) => inner.encode_tagged(tag, rules, out),
            Self::NumericString(inner) => inner.encode_tagged(tag, rules, out),
            Self::PrintableString(inner) => inner.encode_tagged(tag, rules, out),
            Self::Ia5String(inner) => inner.encode_tagged(tag, rules, out),
            Self::UtcTime(inner) => inner.encode_tagged(tag, rules, out),
            Self::GeneralizedTime(inner) => inner.encode_tagged(tag, rules, out),
            Self::VisibleString(inner) => inner.encode_tagged(tag, rules, out),
            Self::UniversalString(inner) => inner.encode_tagged(tag, rules, out),
            Self::BmpString(inner) => inner.encode_tagged(tag, rules, out),
            Self::Date(inner) => inner.encode_tagged(tag, rules, out),
            Self::TimeOfDay(inner) => inner.encode_tagged(tag, rules, out),
            Self::DateTime(inner) => inner.encode_tagged(tag, rules, out),
            Self::Duration(inner) => inner.encode_tagged(tag, rules, out),
            Self::OidIri(inner) => inner.encode_tagged(tag, rules, out),
            Self::RelativeOidIri(inner) => inner.encode_tagged(tag, rules, out),
            Self::SequenceOf(inner) => inner.encode_tagged(tag, rules, out),
            Self::SetOf(inner) => inner.encode_tagged(tag, rules, out),
            Self::Constructed(inner) => inner.encode_tagged(tag, rules, out),
            Self::Unknown(inner) => inner.encode_tagged(tag, rules, out),
        }
    }
}

/// Every variant knows its own identifier: the leaves their universal tag,
/// `Constructed` and `Unknown` the one they were read or built with.
impl Encode for Asn1Object {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Boolean(inner) => inner.encoded_len(rules),
            Self::Integer(inner) => inner.encoded_len(rules),
            Self::BitString(inner) => inner.encoded_len(rules),
            Self::OctetString(inner) => inner.encoded_len(rules),
            Self::Null(inner) => inner.encoded_len(rules),
            Self::Oid(inner) => inner.encoded_len(rules),
            Self::Real(inner) => inner.encoded_len(rules),
            Self::Enumerated(inner) => inner.encoded_len(rules),
            Self::Utf8String(inner) => inner.encoded_len(rules),
            Self::RelativeOid(inner) => inner.encoded_len(rules),
            Self::Time(inner) => inner.encoded_len(rules),
            Self::NumericString(inner) => inner.encoded_len(rules),
            Self::PrintableString(inner) => inner.encoded_len(rules),
            Self::Ia5String(inner) => inner.encoded_len(rules),
            Self::UtcTime(inner) => inner.encoded_len(rules),
            Self::GeneralizedTime(inner) => inner.encoded_len(rules),
            Self::VisibleString(inner) => inner.encoded_len(rules),
            Self::UniversalString(inner) => inner.encoded_len(rules),
            Self::BmpString(inner) => inner.encoded_len(rules),
            Self::Date(inner) => inner.encoded_len(rules),
            Self::TimeOfDay(inner) => inner.encoded_len(rules),
            Self::DateTime(inner) => inner.encoded_len(rules),
            Self::Duration(inner) => inner.encoded_len(rules),
            Self::OidIri(inner) => inner.encoded_len(rules),
            Self::RelativeOidIri(inner) => inner.encoded_len(rules),
            Self::SequenceOf(inner) => inner.encoded_len(rules),
            Self::SetOf(inner) => inner.encoded_len(rules),
            Self::Constructed(inner) => inner.encoded_len(rules),
            Self::Unknown(inner) => inner.encoded_len(rules),
        }
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Boolean(inner) => inner.encode(rules, out),
            Self::Integer(inner) => inner.encode(rules, out),
            Self::BitString(inner) => inner.encode(rules, out),
            Self::OctetString(inner) => inner.encode(rules, out),
            Self::Null(inner) => inner.encode(rules, out),
            Self::Oid(inner) => inner.encode(rules, out),
            Self::Real(inner) => inner.encode(rules, out),
            Self::Enumerated(inner) => inner.encode(rules, out),
            Self::Utf8String(inner) => inner.encode(rules, out),
            Self::RelativeOid(inner) => inner.encode(rules, out),
            Self::Time(inner) => inner.encode(rules, out),
            Self::NumericString(inner) => inner.encode(rules, out),
            Self::PrintableString(inner) => inner.encode(rules, out),
            Self::Ia5String(inner) => inner.encode(rules, out),
            Self::UtcTime(inner) => inner.encode(rules, out),
            Self::GeneralizedTime(inner) => inner.encode(rules, out),
            Self::VisibleString(inner) => inner.encode(rules, out),
            Self::UniversalString(inner) => inner.encode(rules, out),
            Self::BmpString(inner) => inner.encode(rules, out),
            Self::Date(inner) => inner.encode(rules, out),
            Self::TimeOfDay(inner) => inner.encode(rules, out),
            Self::DateTime(inner) => inner.encode(rules, out),
            Self::Duration(inner) => inner.encode(rules, out),
            Self::OidIri(inner) => inner.encode(rules, out),
            Self::RelativeOidIri(inner) => inner.encode(rules, out),
            Self::SequenceOf(inner) => inner.encode(rules, out),
            Self::SetOf(inner) => inner.encode(rules, out),
            Self::Constructed(inner) => inner.encode(rules, out),
            Self::Unknown(inner) => inner.encode(rules, out),
        }
    }
}
