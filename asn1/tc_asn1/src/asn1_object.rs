mod dump;
mod tagged;

pub use tagged::{Asn1Tagged, TaggedContent};

use crate::universal::*;
use crate::{
    Asn1Any, Asn1Class, Asn1Error, Asn1Ref, DecodeConstructed, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeTagged, EncodingOptions,
};
use alloc::vec::Vec;


#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asn1Object {
    Boolean(Asn1Boolean),
    Integer(Asn1Integer),
    BitString(Asn1BitString),
    OctetString(Asn1OctetString),
    Null,
    Oid(Asn1Oid),
    ObjectDescriptor(Asn1ObjectDescriptor),
    External(Asn1External),
    Real(Asn1Real),
    Enumerated(Asn1Enumerated),
    EmbeddedPdv(Asn1EmbeddedPdv),
    Utf8String(Asn1Utf8String),
    RelativeOid(Asn1RelativeOid),
    Time(Asn1Time),
    Sequence(Vec<Asn1Object>),
    Set(Vec<Asn1Object>),
    NumericString(Asn1NumericString),
    PrintableString(Asn1PrintableString),
    TeletexString(Asn1TeletexString),
    VideotexString(Asn1VideotexString),
    Ia5String(Asn1Ia5String),
    UtcTime(Asn1UtcTime),
    GeneralizedTime(Asn1GeneralizedTime),
    GraphicString(Asn1GraphicString),
    VisibleString(Asn1VisibleString),
    GeneralString(Asn1GeneralString),
    UniversalString(Asn1UniversalString),
    CharacterString(Asn1CharacterString),
    BmpString(Asn1BmpString),
    Date(Asn1Date),
    TimeOfDay(Asn1TimeOfDay),
    DateTime(Asn1DateTime),
    Duration(Asn1Duration),
    OidIri(Asn1OidIri),
    RelativeOidIri(Asn1RelativeOidIri),
    /// 非 universal 類別；constructed 解成子元素，primitive 保留內容。
    Tagged(Asn1Tagged),
    /// Unassigned universal tags and unsupported constructed forms of non-string types.
    /// dump 遇到超過 `u64` 的號碼時，以 `tag=` 加完整十六進位識別位元組顯示。
    /// Raw encodings are not canonicalised under CER either.
    Unknown(Asn1Any),
}

macro_rules! from_leaf {
    ($($variant:ident: $ty:ty),* $(,)?) => {$(
        impl From<$ty> for Asn1Object {
            /// 接收葉節點的所有權。變動時間：分支只依編碼結構。
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        }
    )*};
}
from_leaf! {
    Boolean: Asn1Boolean,
    Integer: Asn1Integer,
    BitString: Asn1BitString,
    OctetString: Asn1OctetString,
    Oid: Asn1Oid,
    ObjectDescriptor: Asn1ObjectDescriptor,
    External: Asn1External,
    Real: Asn1Real,
    Enumerated: Asn1Enumerated,
    EmbeddedPdv: Asn1EmbeddedPdv,
    Utf8String: Asn1Utf8String,
    RelativeOid: Asn1RelativeOid,
    Time: Asn1Time,
    NumericString: Asn1NumericString,
    PrintableString: Asn1PrintableString,
    TeletexString: Asn1TeletexString,
    VideotexString: Asn1VideotexString,
    Ia5String: Asn1Ia5String,
    UtcTime: Asn1UtcTime,
    GeneralizedTime: Asn1GeneralizedTime,
    GraphicString: Asn1GraphicString,
    VisibleString: Asn1VisibleString,
    GeneralString: Asn1GeneralString,
    UniversalString: Asn1UniversalString,
    CharacterString: Asn1CharacterString,
    BmpString: Asn1BmpString,
    Date: Asn1Date,
    TimeOfDay: Asn1TimeOfDay,
    DateTime: Asn1DateTime,
    Duration: Asn1Duration,
    OidIri: Asn1OidIri,
    RelativeOidIri: Asn1RelativeOidIri,
    Tagged: Asn1Tagged,
}
impl From<Asn1Null> for Asn1Object {
    /// 建立 NULL 節點。變動時間：分支只依編碼結構。
    fn from(_: Asn1Null) -> Self {
        Self::Null
    }
}

impl Asn1Object {
    /// 借用 Sequence 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_sequence(&self) -> Option<&[Asn1Object]> {
        match self {
            Self::Sequence(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 Set 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_set(&self) -> Option<&[Asn1Object]> {
        match self {
            Self::Set(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 Integer 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_integer(&self) -> Option<&Asn1Integer> {
        match self {
            Self::Integer(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 Oid 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_oid(&self) -> Option<&Asn1Oid> {
        match self {
            Self::Oid(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 OctetString 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_octet_string(&self) -> Option<&Asn1OctetString> {
        match self {
            Self::OctetString(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 BitString 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_bit_string(&self) -> Option<&Asn1BitString> {
        match self {
            Self::BitString(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 Tagged 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_tagged(&self) -> Option<&Asn1Tagged> {
        match self {
            Self::Tagged(value) => Some(value),
            _ => None,
        }
    }

    /// 把借用的元素整棵解開。變動時間：分支只依編碼結構。
    ///
    /// # Examples
    ///
    /// [`Asn1Any`] 保存的原始元素可以另行解讀，原資料仍保留。
    ///
    /// ```
    /// use tc_asn1::{Decode, Asn1Any, Asn1Object, DecodingContext, DecodingOptions, DecodeInner};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    ///
    /// let (_, any) = Asn1Any::decode(&[2, 1, 7], &DecodingOptions::default()).unwrap();
    /// let tree = Asn1Object::from_ref(&any.as_ref(), &mut context).unwrap();
    /// assert_eq!(i64::try_from(tree.as_integer().unwrap()), Ok(7));
    /// assert_eq!(any.raw(), [2, 1, 7]);
    /// ```
    pub fn from_ref(
        element: &Asn1Ref<'_>,
        context: &mut DecodingContext<'_>,
    ) -> Result<Self, Asn1Error> {
        context.options().check_content_len(element.value().len())?;
        if element.class() != Asn1Class::Universal {
            return Ok(Self::Tagged(Asn1Tagged::from_ref(element, context)?));
        }
        Ok(match element.tag() {
            tag::BOOLEAN => Self::Boolean(crate::decoding::content::<Asn1Boolean>(
                element.value(),
                context,
            )?),
            tag::INTEGER => Self::Integer(crate::decoding::content::<Asn1Integer>(
                element.value(),
                context,
            )?),
            tag::BIT_STRING => Self::BitString(crate::decoding::content::<Asn1BitString>(
                element.value(),
                context,
            )?),
            tag::OCTET_STRING => Self::OctetString(crate::decoding::content::<Asn1OctetString>(
                element.value(),
                context,
            )?),
            tag::CONSTRUCTED_OCTET_STRING => Self::OctetString(
                Asn1OctetString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_BIT_STRING => {
                Self::BitString(Asn1BitString::decode_constructed(element.value(), context)?)
            }
            tag::NULL => {
                crate::decoding::content::<Asn1Null>(element.value(), context)?;
                Self::Null
            }
            tag::OBJECT_IDENTIFIER => Self::Oid(crate::decoding::content::<Asn1Oid>(
                element.value(),
                context,
            )?),
            tag::OBJECT_DESCRIPTOR => Self::ObjectDescriptor(crate::decoding::content::<
                Asn1ObjectDescriptor,
            >(
                element.value(), context
            )?),
            tag::EXTERNAL => Self::External(crate::decoding::content::<Asn1External>(
                element.value(),
                context,
            )?),
            tag::REAL => Self::Real(crate::decoding::content::<Asn1Real>(
                element.value(),
                context,
            )?),
            tag::ENUMERATED => Self::Enumerated(crate::decoding::content::<Asn1Enumerated>(
                element.value(),
                context,
            )?),
            tag::EMBEDDED_PDV => Self::EmbeddedPdv(crate::decoding::content::<Asn1EmbeddedPdv>(
                element.value(),
                context,
            )?),
            tag::UTF8_STRING => Self::Utf8String(crate::decoding::content::<Asn1Utf8String>(
                element.value(),
                context,
            )?),
            tag::RELATIVE_OID => Self::RelativeOid(crate::decoding::content::<Asn1RelativeOid>(
                element.value(),
                context,
            )?),
            tag::TIME => Self::Time(crate::decoding::content::<Asn1Time>(
                element.value(),
                context,
            )?),
            tag::SEQUENCE => Self::Sequence(decode_children(element, context)?),
            tag::SET => Self::Set(decode_children(element, context)?),
            tag::NUMERIC_STRING => Self::NumericString(crate::decoding::content::<
                Asn1NumericString,
            >(element.value(), context)?),
            tag::PRINTABLE_STRING => Self::PrintableString(crate::decoding::content::<
                Asn1PrintableString,
            >(element.value(), context)?),
            tag::TELETEX_STRING => Self::TeletexString(crate::decoding::content::<
                Asn1TeletexString,
            >(element.value(), context)?),
            tag::VIDEOTEX_STRING => Self::VideotexString(crate::decoding::content::<
                Asn1VideotexString,
            >(element.value(), context)?),
            tag::IA5_STRING => Self::Ia5String(crate::decoding::content::<Asn1Ia5String>(
                element.value(),
                context,
            )?),
            tag::UTC_TIME => Self::UtcTime(crate::decoding::content::<Asn1UtcTime>(
                element.value(),
                context,
            )?),
            tag::GENERALIZED_TIME => Self::GeneralizedTime(crate::decoding::content::<
                Asn1GeneralizedTime,
            >(element.value(), context)?),
            tag::GRAPHIC_STRING => Self::GraphicString(crate::decoding::content::<
                Asn1GraphicString,
            >(element.value(), context)?),
            tag::VISIBLE_STRING => Self::VisibleString(crate::decoding::content::<
                Asn1VisibleString,
            >(element.value(), context)?),
            tag::GENERAL_STRING => Self::GeneralString(crate::decoding::content::<
                Asn1GeneralString,
            >(element.value(), context)?),
            tag::UNIVERSAL_STRING => Self::UniversalString(crate::decoding::content::<
                Asn1UniversalString,
            >(element.value(), context)?),
            tag::CHARACTER_STRING => Self::CharacterString(crate::decoding::content::<
                Asn1CharacterString,
            >(element.value(), context)?),
            tag::BMP_STRING => Self::BmpString(crate::decoding::content::<Asn1BmpString>(
                element.value(),
                context,
            )?),
            tag::DATE => Self::Date(crate::decoding::content::<Asn1Date>(
                element.value(),
                context,
            )?),
            tag::TIME_OF_DAY => Self::TimeOfDay(crate::decoding::content::<Asn1TimeOfDay>(
                element.value(),
                context,
            )?),
            tag::DATE_TIME => Self::DateTime(crate::decoding::content::<Asn1DateTime>(
                element.value(),
                context,
            )?),
            tag::DURATION => Self::Duration(crate::decoding::content::<Asn1Duration>(
                element.value(),
                context,
            )?),
            tag::OID_IRI => Self::OidIri(crate::decoding::content::<Asn1OidIri>(
                element.value(),
                context,
            )?),
            tag::RELATIVE_OID_IRI => Self::RelativeOidIri(crate::decoding::content::<
                Asn1RelativeOidIri,
            >(element.value(), context)?),
            tag::CONSTRUCTED_OBJECT_DESCRIPTOR => Self::ObjectDescriptor(
                Asn1ObjectDescriptor::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_UTF8_STRING => Self::Utf8String(Asn1Utf8String::decode_constructed(
                element.value(),
                context,
            )?),
            tag::CONSTRUCTED_NUMERIC_STRING => Self::NumericString(
                Asn1NumericString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_PRINTABLE_STRING => Self::PrintableString(
                Asn1PrintableString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_TELETEX_STRING => Self::TeletexString(
                Asn1TeletexString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_VIDEOTEX_STRING => Self::VideotexString(
                Asn1VideotexString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_IA5_STRING => {
                Self::Ia5String(Asn1Ia5String::decode_constructed(element.value(), context)?)
            }
            tag::CONSTRUCTED_GRAPHIC_STRING => Self::GraphicString(
                Asn1GraphicString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_VISIBLE_STRING => Self::VisibleString(
                Asn1VisibleString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_GENERAL_STRING => Self::GeneralString(
                Asn1GeneralString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_UNIVERSAL_STRING => Self::UniversalString(
                Asn1UniversalString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_BMP_STRING => {
                Self::BmpString(Asn1BmpString::decode_constructed(element.value(), context)?)
            }
            _ => Self::Unknown(Asn1Any::from(element)),
        })
    }
    /// Interpret this view using DER validation for known types and child TLVs.
    /// Unknown IMPLICIT contents still require a schema. Variable time: public
    /// input only; no constant-time alternative is provided.
    pub fn from_ref_der(
        element: &Asn1Ref<'_>,
        context: &mut DecodingContext<'_>,
    ) -> Result<Self, Asn1Error> {
        Asn1Ref::parse_der(element.raw(), context)?;
        if element.class() != Asn1Class::Universal {
            return Ok(Self::Tagged(Asn1Tagged::from_ref_der(element, context)?));
        }
        let decoded = match element.tag() {
            tag::BOOLEAN => {
                Self::Boolean(Asn1Boolean::decode_content_der(element.value(), context)?)
            }
            tag::INTEGER => {
                Self::Integer(Asn1Integer::decode_content_der(element.value(), context)?)
            }
            tag::BIT_STRING => {
                Self::BitString(Asn1BitString::decode_content_der(element.value(), context)?)
            }
            tag::OCTET_STRING => Self::OctetString(Asn1OctetString::decode_content_der(
                element.value(),
                context,
            )?),
            tag::CONSTRUCTED_OCTET_STRING => Self::OctetString(
                Asn1OctetString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_BIT_STRING => {
                Self::BitString(Asn1BitString::decode_constructed(element.value(), context)?)
            }
            tag::NULL => {
                Asn1Null::decode_content_der(element.value(), context)?;
                Self::Null
            }
            tag::OBJECT_IDENTIFIER => {
                Self::Oid(Asn1Oid::decode_content_der(element.value(), context)?)
            }
            tag::OBJECT_DESCRIPTOR => Self::ObjectDescriptor(crate::decoding::content::<
                Asn1ObjectDescriptor,
            >(
                element.value(), context
            )?),
            tag::EXTERNAL => {
                Self::External(Asn1External::decode_content_der(element.value(), context)?)
            }
            tag::REAL => Self::Real(Asn1Real::decode_content_der(element.value(), context)?),
            tag::ENUMERATED => Self::Enumerated(Asn1Enumerated::decode_content_der(
                element.value(),
                context,
            )?),
            tag::EMBEDDED_PDV => Self::EmbeddedPdv(Asn1EmbeddedPdv::decode_content_der(
                element.value(),
                context,
            )?),
            tag::UTF8_STRING => Self::Utf8String(Asn1Utf8String::decode_content_der(
                element.value(),
                context,
            )?),
            tag::RELATIVE_OID => Self::RelativeOid(Asn1RelativeOid::decode_content_der(
                element.value(),
                context,
            )?),
            tag::TIME => Self::Time(Asn1Time::decode_content_der(element.value(), context)?),
            tag::SEQUENCE => Self::Sequence(decode_children_der(element, context)?),
            tag::SET => Self::Set(decode_children_der(element, context)?),
            tag::NUMERIC_STRING => Self::NumericString(crate::decoding::content::<
                Asn1NumericString,
            >(element.value(), context)?),
            tag::PRINTABLE_STRING => Self::PrintableString(crate::decoding::content::<
                Asn1PrintableString,
            >(element.value(), context)?),
            tag::TELETEX_STRING => Self::TeletexString(crate::decoding::content::<
                Asn1TeletexString,
            >(element.value(), context)?),
            tag::VIDEOTEX_STRING => Self::VideotexString(crate::decoding::content::<
                Asn1VideotexString,
            >(element.value(), context)?),
            tag::IA5_STRING => {
                Self::Ia5String(Asn1Ia5String::decode_content_der(element.value(), context)?)
            }
            tag::UTC_TIME => {
                Self::UtcTime(Asn1UtcTime::decode_content_der(element.value(), context)?)
            }
            tag::GENERALIZED_TIME => Self::GeneralizedTime(crate::decoding::content::<
                Asn1GeneralizedTime,
            >(element.value(), context)?),
            tag::GRAPHIC_STRING => Self::GraphicString(crate::decoding::content::<
                Asn1GraphicString,
            >(element.value(), context)?),
            tag::VISIBLE_STRING => Self::VisibleString(crate::decoding::content::<
                Asn1VisibleString,
            >(element.value(), context)?),
            tag::GENERAL_STRING => Self::GeneralString(crate::decoding::content::<
                Asn1GeneralString,
            >(element.value(), context)?),
            tag::UNIVERSAL_STRING => Self::UniversalString(crate::decoding::content::<
                Asn1UniversalString,
            >(element.value(), context)?),
            tag::CHARACTER_STRING => Self::CharacterString(crate::decoding::content::<
                Asn1CharacterString,
            >(element.value(), context)?),
            tag::BMP_STRING => {
                Self::BmpString(Asn1BmpString::decode_content_der(element.value(), context)?)
            }
            tag::DATE => Self::Date(Asn1Date::decode_content_der(element.value(), context)?),
            tag::TIME_OF_DAY => {
                Self::TimeOfDay(Asn1TimeOfDay::decode_content_der(element.value(), context)?)
            }
            tag::DATE_TIME => {
                Self::DateTime(Asn1DateTime::decode_content_der(element.value(), context)?)
            }
            tag::DURATION => {
                Self::Duration(Asn1Duration::decode_content_der(element.value(), context)?)
            }
            tag::OID_IRI => Self::OidIri(Asn1OidIri::decode_content_der(element.value(), context)?),
            tag::RELATIVE_OID_IRI => Self::RelativeOidIri(crate::decoding::content::<
                Asn1RelativeOidIri,
            >(element.value(), context)?),
            tag::CONSTRUCTED_OBJECT_DESCRIPTOR => Self::ObjectDescriptor(
                Asn1ObjectDescriptor::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_UTF8_STRING => Self::Utf8String(Asn1Utf8String::decode_constructed(
                element.value(),
                context,
            )?),
            tag::CONSTRUCTED_NUMERIC_STRING => Self::NumericString(
                Asn1NumericString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_PRINTABLE_STRING => Self::PrintableString(
                Asn1PrintableString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_TELETEX_STRING => Self::TeletexString(
                Asn1TeletexString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_VIDEOTEX_STRING => Self::VideotexString(
                Asn1VideotexString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_IA5_STRING => {
                Self::Ia5String(Asn1Ia5String::decode_constructed(element.value(), context)?)
            }
            tag::CONSTRUCTED_GRAPHIC_STRING => Self::GraphicString(
                Asn1GraphicString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_VISIBLE_STRING => Self::VisibleString(
                Asn1VisibleString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_GENERAL_STRING => Self::GeneralString(
                Asn1GeneralString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_UNIVERSAL_STRING => Self::UniversalString(
                Asn1UniversalString::decode_constructed(element.value(), context)?,
            ),
            tag::CONSTRUCTED_BMP_STRING => {
                Self::BmpString(Asn1BmpString::decode_constructed(element.value(), context)?)
            }
            _ => {
                if element.is_constructed() {
                    decode_children_der(element, context)?;
                }
                Self::Unknown(Asn1Any::from(element))
            }
        };
        let canonical = crate::EncodeContent::encode_content_to_vec(
            &decoded,
            &EncodingOptions::new(crate::EncodingType::Der),
        )?;
        if canonical != element.value() {
            return Err(Asn1Error::NotDer);
        }
        Ok(decoded)
    }
}

impl<'a> DecodeInner<'a> for Asn1Object {
    /// 解讀第一個完整元素。變動時間：分支只依編碼結構。
    fn decode_inner(
        buff: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        Ok((element.total_len(), Self::from_ref(&element, context)?))
    }
    fn decode_inner_der(
        buff: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse_der(buff, context)?;
        let decoded = Self::from_ref_der(&element, context)?;
        Ok((element.total_len(), decoded))
    }
}
impl<'a> crate::Decode<'a> for Asn1Object {
    fn decode(
        buff: &'a [u8],
        options: &crate::DecodingOptions,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        <Self as crate::DecodeInner<'a>>::decode_inner(
            buff,
            &mut crate::DecodingContext::new(options),
        )
    }
}

impl Asn1Object {
    /// 取得識別位元組。變動時間：分支只依編碼結構，未知節點委派原始元素。
    pub fn tag(&self) -> &[u8] {
        match self {
            Self::Boolean(_) => tag::BOOLEAN,
            Self::Integer(_) => tag::INTEGER,
            Self::BitString(_) => tag::BIT_STRING,
            Self::OctetString(_) => tag::OCTET_STRING,
            Self::Null => tag::NULL,
            Self::Oid(_) => tag::OBJECT_IDENTIFIER,
            Self::ObjectDescriptor(_) => tag::OBJECT_DESCRIPTOR,
            Self::External(_) => tag::EXTERNAL,
            Self::Real(_) => tag::REAL,
            Self::Enumerated(_) => tag::ENUMERATED,
            Self::EmbeddedPdv(_) => tag::EMBEDDED_PDV,
            Self::Utf8String(_) => tag::UTF8_STRING,
            Self::RelativeOid(_) => tag::RELATIVE_OID,
            Self::Time(_) => tag::TIME,
            Self::Sequence(_) => tag::SEQUENCE,
            Self::Set(_) => tag::SET,
            Self::NumericString(_) => tag::NUMERIC_STRING,
            Self::PrintableString(_) => tag::PRINTABLE_STRING,
            Self::TeletexString(_) => tag::TELETEX_STRING,
            Self::VideotexString(_) => tag::VIDEOTEX_STRING,
            Self::Ia5String(_) => tag::IA5_STRING,
            Self::UtcTime(_) => tag::UTC_TIME,
            Self::GeneralizedTime(_) => tag::GENERALIZED_TIME,
            Self::GraphicString(_) => tag::GRAPHIC_STRING,
            Self::VisibleString(_) => tag::VISIBLE_STRING,
            Self::GeneralString(_) => tag::GENERAL_STRING,
            Self::UniversalString(_) => tag::UNIVERSAL_STRING,
            Self::CharacterString(_) => tag::CHARACTER_STRING,
            Self::BmpString(_) => tag::BMP_STRING,
            Self::Date(_) => tag::DATE,
            Self::TimeOfDay(_) => tag::TIME_OF_DAY,
            Self::DateTime(_) => tag::DATE_TIME,
            Self::Duration(_) => tag::DURATION,
            Self::OidIri(_) => tag::OID_IRI,
            Self::RelativeOidIri(_) => tag::RELATIVE_OID_IRI,
            Self::Tagged(value) => value.tag(),
            Self::Unknown(value) => value.as_ref().tag(),
        }
    }
}

impl crate::EncodeContent for Asn1Object {
    /// 計算內容長度。變動時間：分支只依編碼結構。
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Null => 0,
            Self::Sequence(children) | Self::Set(children) => children_len(children, rules),
            Self::Boolean(value) => value.content_len(rules),
            Self::Integer(value) => value.content_len(rules),
            Self::BitString(value) => value.content_len(rules),
            Self::OctetString(value) => value.content_len(rules),
            Self::Oid(value) => value.content_len(rules),
            Self::ObjectDescriptor(value) => value.content_len(rules),
            Self::External(value) => value.content_len(rules),
            Self::Real(value) => value.content_len(rules),
            Self::Enumerated(value) => value.content_len(rules),
            Self::EmbeddedPdv(value) => value.content_len(rules),
            Self::Utf8String(value) => value.content_len(rules),
            Self::RelativeOid(value) => value.content_len(rules),
            Self::Time(value) => value.content_len(rules),
            Self::NumericString(value) => value.content_len(rules),
            Self::PrintableString(value) => value.content_len(rules),
            Self::TeletexString(value) => value.content_len(rules),
            Self::VideotexString(value) => value.content_len(rules),
            Self::Ia5String(value) => value.content_len(rules),
            Self::UtcTime(value) => value.content_len(rules),
            Self::GeneralizedTime(value) => value.content_len(rules),
            Self::GraphicString(value) => value.content_len(rules),
            Self::VisibleString(value) => value.content_len(rules),
            Self::GeneralString(value) => value.content_len(rules),
            Self::UniversalString(value) => value.content_len(rules),
            Self::CharacterString(value) => value.content_len(rules),
            Self::BmpString(value) => value.content_len(rules),
            Self::Date(value) => value.content_len(rules),
            Self::TimeOfDay(value) => value.content_len(rules),
            Self::DateTime(value) => value.content_len(rules),
            Self::Duration(value) => value.content_len(rules),
            Self::OidIri(value) => value.content_len(rules),
            Self::RelativeOidIri(value) => value.content_len(rules),
            Self::Tagged(value) => value.content_len(rules),
            Self::Unknown(value) => value.content_len(rules),
        }
    }

    /// 寫入內容。變動時間：分支只依編碼結構，SET 排序另比較公開編碼內容。
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = crate::EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        match self {
            Self::Null => Ok(0),
            Self::Set(children) if rules.is_canonical() => {
                let mut encodings = children
                    .iter()
                    .map(|member| Ok((tag_key(member.tag())?, encode_member(member, rules)?)))
                    .collect::<Result<Vec<_>, Asn1Error>>()?;
                encodings.sort();
                copy_encodings(encodings.iter().map(|(_, bytes)| bytes.as_slice()), out)
            }
            Self::Sequence(children) | Self::Set(children) => encode_children(children, rules, out),
            Self::Boolean(value) => value.encode_content(rules, out),
            Self::Integer(value) => value.encode_content(rules, out),
            Self::BitString(value) => value.encode_content(rules, out),
            Self::OctetString(value) => value.encode_content(rules, out),
            Self::Oid(value) => value.encode_content(rules, out),
            Self::ObjectDescriptor(value) => value.encode_content(rules, out),
            Self::External(value) => value.encode_content(rules, out),
            Self::Real(value) => value.encode_content(rules, out),
            Self::Enumerated(value) => value.encode_content(rules, out),
            Self::EmbeddedPdv(value) => value.encode_content(rules, out),
            Self::Utf8String(value) => value.encode_content(rules, out),
            Self::RelativeOid(value) => value.encode_content(rules, out),
            Self::Time(value) => value.encode_content(rules, out),
            Self::NumericString(value) => value.encode_content(rules, out),
            Self::PrintableString(value) => value.encode_content(rules, out),
            Self::TeletexString(value) => value.encode_content(rules, out),
            Self::VideotexString(value) => value.encode_content(rules, out),
            Self::Ia5String(value) => value.encode_content(rules, out),
            Self::UtcTime(value) => value.encode_content(rules, out),
            Self::GeneralizedTime(value) => value.encode_content(rules, out),
            Self::GraphicString(value) => value.encode_content(rules, out),
            Self::VisibleString(value) => value.encode_content(rules, out),
            Self::GeneralString(value) => value.encode_content(rules, out),
            Self::UniversalString(value) => value.encode_content(rules, out),
            Self::CharacterString(value) => value.encode_content(rules, out),
            Self::BmpString(value) => value.encode_content(rules, out),
            Self::Date(value) => value.encode_content(rules, out),
            Self::TimeOfDay(value) => value.encode_content(rules, out),
            Self::DateTime(value) => value.encode_content(rules, out),
            Self::Duration(value) => value.encode_content(rules, out),
            Self::OidIri(value) => value.encode_content(rules, out),
            Self::RelativeOidIri(value) => value.encode_content(rules, out),
            Self::Tagged(value) => value.encode_content(rules, out),
            Self::Unknown(value) => value.encode_content(rules, out),
        }
    }
}

impl crate::EncodeTagged for Asn1Object {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        match self {
            Self::Boolean(value) => value.encoded_len_tagged(tag, rules),
            Self::Integer(value) => value.encoded_len_tagged(tag, rules),
            Self::BitString(value) => value.encoded_len_tagged(tag, rules),
            Self::OctetString(value) => value.encoded_len_tagged(tag, rules),
            Self::Oid(value) => value.encoded_len_tagged(tag, rules),
            Self::ObjectDescriptor(value) => value.encoded_len_tagged(tag, rules),
            Self::External(value) => value.encoded_len_tagged(tag, rules),
            Self::Real(value) => value.encoded_len_tagged(tag, rules),
            Self::Enumerated(value) => value.encoded_len_tagged(tag, rules),
            Self::EmbeddedPdv(value) => value.encoded_len_tagged(tag, rules),
            Self::Utf8String(value) => value.encoded_len_tagged(tag, rules),
            Self::RelativeOid(value) => value.encoded_len_tagged(tag, rules),
            Self::Time(value) => value.encoded_len_tagged(tag, rules),
            Self::NumericString(value) => value.encoded_len_tagged(tag, rules),
            Self::PrintableString(value) => value.encoded_len_tagged(tag, rules),
            Self::TeletexString(value) => value.encoded_len_tagged(tag, rules),
            Self::VideotexString(value) => value.encoded_len_tagged(tag, rules),
            Self::Ia5String(value) => value.encoded_len_tagged(tag, rules),
            Self::UtcTime(value) => value.encoded_len_tagged(tag, rules),
            Self::GeneralizedTime(value) => value.encoded_len_tagged(tag, rules),
            Self::GraphicString(value) => value.encoded_len_tagged(tag, rules),
            Self::VisibleString(value) => value.encoded_len_tagged(tag, rules),
            Self::GeneralString(value) => value.encoded_len_tagged(tag, rules),
            Self::UniversalString(value) => value.encoded_len_tagged(tag, rules),
            Self::CharacterString(value) => value.encoded_len_tagged(tag, rules),
            Self::BmpString(value) => value.encoded_len_tagged(tag, rules),
            Self::Date(value) => value.encoded_len_tagged(tag, rules),
            Self::TimeOfDay(value) => value.encoded_len_tagged(tag, rules),
            Self::DateTime(value) => value.encoded_len_tagged(tag, rules),
            Self::Duration(value) => value.encoded_len_tagged(tag, rules),
            Self::OidIri(value) => value.encoded_len_tagged(tag, rules),
            Self::RelativeOidIri(value) => value.encoded_len_tagged(tag, rules),
            Self::Tagged(value) => value.encoded_len_tagged(tag, rules),
            Self::Unknown(value) => value.encoded_len_tagged(tag, rules),
            Self::Null | Self::Sequence(_) | Self::Set(_) => {
                crate::encoding::default_encoded_len(self, tag, rules)
            }
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        match self {
            Self::Boolean(value) => value.encode_tagged(tag, rules, out),
            Self::Integer(value) => value.encode_tagged(tag, rules, out),
            Self::BitString(value) => value.encode_tagged(tag, rules, out),
            Self::OctetString(value) => value.encode_tagged(tag, rules, out),
            Self::Oid(value) => value.encode_tagged(tag, rules, out),
            Self::ObjectDescriptor(value) => value.encode_tagged(tag, rules, out),
            Self::External(value) => value.encode_tagged(tag, rules, out),
            Self::Real(value) => value.encode_tagged(tag, rules, out),
            Self::Enumerated(value) => value.encode_tagged(tag, rules, out),
            Self::EmbeddedPdv(value) => value.encode_tagged(tag, rules, out),
            Self::Utf8String(value) => value.encode_tagged(tag, rules, out),
            Self::RelativeOid(value) => value.encode_tagged(tag, rules, out),
            Self::Time(value) => value.encode_tagged(tag, rules, out),
            Self::NumericString(value) => value.encode_tagged(tag, rules, out),
            Self::PrintableString(value) => value.encode_tagged(tag, rules, out),
            Self::TeletexString(value) => value.encode_tagged(tag, rules, out),
            Self::VideotexString(value) => value.encode_tagged(tag, rules, out),
            Self::Ia5String(value) => value.encode_tagged(tag, rules, out),
            Self::UtcTime(value) => value.encode_tagged(tag, rules, out),
            Self::GeneralizedTime(value) => value.encode_tagged(tag, rules, out),
            Self::GraphicString(value) => value.encode_tagged(tag, rules, out),
            Self::VisibleString(value) => value.encode_tagged(tag, rules, out),
            Self::GeneralString(value) => value.encode_tagged(tag, rules, out),
            Self::UniversalString(value) => value.encode_tagged(tag, rules, out),
            Self::CharacterString(value) => value.encode_tagged(tag, rules, out),
            Self::BmpString(value) => value.encode_tagged(tag, rules, out),
            Self::Date(value) => value.encode_tagged(tag, rules, out),
            Self::TimeOfDay(value) => value.encode_tagged(tag, rules, out),
            Self::DateTime(value) => value.encode_tagged(tag, rules, out),
            Self::Duration(value) => value.encode_tagged(tag, rules, out),
            Self::OidIri(value) => value.encode_tagged(tag, rules, out),
            Self::RelativeOidIri(value) => value.encode_tagged(tag, rules, out),
            Self::Tagged(value) => value.encode_tagged(tag, rules, out),
            Self::Unknown(value) => value.encode_tagged(tag, rules, out),
            Self::Null | Self::Sequence(_) | Self::Set(_) => {
                crate::encoding::default_encode(self, tag, rules, out)
            }
        }
    }
}

impl Encode for Asn1Object {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Boolean(value) => value.encoded_len(rules),
            Self::Integer(value) => value.encoded_len(rules),
            Self::BitString(value) => value.encoded_len(rules),
            Self::OctetString(value) => value.encoded_len(rules),
            Self::Oid(value) => value.encoded_len(rules),
            Self::ObjectDescriptor(value) => value.encoded_len(rules),
            Self::External(value) => value.encoded_len(rules),
            Self::Real(value) => value.encoded_len(rules),
            Self::Enumerated(value) => value.encoded_len(rules),
            Self::EmbeddedPdv(value) => value.encoded_len(rules),
            Self::Utf8String(value) => value.encoded_len(rules),
            Self::RelativeOid(value) => value.encoded_len(rules),
            Self::Time(value) => value.encoded_len(rules),
            Self::NumericString(value) => value.encoded_len(rules),
            Self::PrintableString(value) => value.encoded_len(rules),
            Self::TeletexString(value) => value.encoded_len(rules),
            Self::VideotexString(value) => value.encoded_len(rules),
            Self::Ia5String(value) => value.encoded_len(rules),
            Self::UtcTime(value) => value.encoded_len(rules),
            Self::GeneralizedTime(value) => value.encoded_len(rules),
            Self::GraphicString(value) => value.encoded_len(rules),
            Self::VisibleString(value) => value.encoded_len(rules),
            Self::GeneralString(value) => value.encoded_len(rules),
            Self::UniversalString(value) => value.encoded_len(rules),
            Self::CharacterString(value) => value.encoded_len(rules),
            Self::BmpString(value) => value.encoded_len(rules),
            Self::Date(value) => value.encoded_len(rules),
            Self::TimeOfDay(value) => value.encoded_len(rules),
            Self::DateTime(value) => value.encoded_len(rules),
            Self::Duration(value) => value.encoded_len(rules),
            Self::OidIri(value) => value.encoded_len(rules),
            Self::RelativeOidIri(value) => value.encoded_len(rules),
            Self::Tagged(value) => value.encoded_len(rules),
            Self::Unknown(value) => value.encoded_len(rules),
            Self::Null => self.encoded_len_tagged(tag::NULL, rules),
            Self::Sequence(_) => self.encoded_len_tagged(tag::SEQUENCE, rules),
            Self::Set(_) => self.encoded_len_tagged(tag::SET, rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Boolean(value) => value.encode(rules, out),
            Self::Integer(value) => value.encode(rules, out),
            Self::BitString(value) => value.encode(rules, out),
            Self::OctetString(value) => value.encode(rules, out),
            Self::Oid(value) => value.encode(rules, out),
            Self::ObjectDescriptor(value) => value.encode(rules, out),
            Self::External(value) => value.encode(rules, out),
            Self::Real(value) => value.encode(rules, out),
            Self::Enumerated(value) => value.encode(rules, out),
            Self::EmbeddedPdv(value) => value.encode(rules, out),
            Self::Utf8String(value) => value.encode(rules, out),
            Self::RelativeOid(value) => value.encode(rules, out),
            Self::Time(value) => value.encode(rules, out),
            Self::NumericString(value) => value.encode(rules, out),
            Self::PrintableString(value) => value.encode(rules, out),
            Self::TeletexString(value) => value.encode(rules, out),
            Self::VideotexString(value) => value.encode(rules, out),
            Self::Ia5String(value) => value.encode(rules, out),
            Self::UtcTime(value) => value.encode(rules, out),
            Self::GeneralizedTime(value) => value.encode(rules, out),
            Self::GraphicString(value) => value.encode(rules, out),
            Self::VisibleString(value) => value.encode(rules, out),
            Self::GeneralString(value) => value.encode(rules, out),
            Self::UniversalString(value) => value.encode(rules, out),
            Self::CharacterString(value) => value.encode(rules, out),
            Self::BmpString(value) => value.encode(rules, out),
            Self::Date(value) => value.encode(rules, out),
            Self::TimeOfDay(value) => value.encode(rules, out),
            Self::DateTime(value) => value.encode(rules, out),
            Self::Duration(value) => value.encode(rules, out),
            Self::OidIri(value) => value.encode(rules, out),
            Self::RelativeOidIri(value) => value.encode(rules, out),
            Self::Tagged(value) => value.encode(rules, out),
            Self::Unknown(value) => value.encode(rules, out),
            Self::Null => self.encode_tagged(tag::NULL, rules, out),
            Self::Sequence(_) => self.encode_tagged(tag::SEQUENCE, rules, out),
            Self::Set(_) => self.encode_tagged(tag::SET, rules, out),
        }
    }
}

fn decode_children(
    element: &Asn1Ref<'_>,
    context: &mut DecodingContext<'_>,
) -> Result<Vec<Asn1Object>, Asn1Error> {
    context.with_child(|context| {
        let mut children = crate::asn1_ref::ChildCursor::new(element.value(), context.options());
        let mut values = Vec::new();
        while let Some(child) = children.next(context) {
            values.push(Asn1Object::from_ref(&child?, context)?);
        }
        Ok(values)
    })
}
fn decode_children_der(
    element: &Asn1Ref<'_>,
    context: &mut DecodingContext<'_>,
) -> Result<Vec<Asn1Object>, Asn1Error> {
    context.with_child(|context| {
        let mut children = crate::asn1_ref::ChildCursor::new(element.value(), context.options());
        let mut values = Vec::new();
        while let Some(child) = children.next(context) {
            values.push(Asn1Object::from_ref_der(&child?, context)?);
        }
        Ok(values)
    })
}

fn children_len(children: &[Asn1Object], rules: &EncodingOptions) -> usize {
    children.iter().map(|child| child.encoded_len(rules)).sum()
}

fn encode_children(
    children: &[Asn1Object],
    rules: &EncodingOptions,
    out: &mut [u8],
) -> Result<usize, Asn1Error> {
    let mut at = 0;
    for child in children {
        at += child.encode(rules, out.get_mut(at..).ok_or(Asn1Error::BufferTooSmall)?)?;
    }
    Ok(at)
}
