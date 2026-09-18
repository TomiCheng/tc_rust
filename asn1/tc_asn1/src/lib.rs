#![no_std]

extern crate alloc;

mod asn1_any;
mod asn1_constructed;
mod asn1_object;
mod asn1_ref;
mod decoding;
mod decoding_context;
mod decoding_options;
mod encoding_options;
mod encoding_type;
mod error;
mod schema;
// mod segments;
mod traits;
mod universal;

pub use asn1_any::Asn1Any;
pub use asn1_constructed::Asn1Constructed;
pub use asn1_object::Asn1Object;
pub use asn1_ref::{Asn1Class, Asn1Ref, Children};
pub use decoding_context::DecodingContext;
pub use decoding_options::DecodingOptions;
pub use encoding_options::EncodingOptions;
pub use encoding_type::{EncodingType, LengthForm};
pub use error::Asn1Error;

pub use traits::{
    Decode, DecodeConstructed, DecodeContent, DecodeInner, Encode, EncodeContent, EncodeTagged,
};
pub use universal::tag;
pub use universal::{
    Arcs,
    Asn1BitString,
    Asn1BmpString,
    Asn1Boolean,
    Asn1Date,
    Asn1DateTime,
    Asn1Duration,
    Asn1Enumerated,
    Asn1GeneralizedTime,
    Asn1Ia5String,
    Asn1Integer,
    Asn1Null,
    Asn1NumericString,
    Asn1OctetString,
    Asn1Oid,
    Asn1OidIri,
    Asn1PrintableString,
    Asn1Real,
    Asn1RelativeOid,
    Asn1RelativeOidIri,
    Asn1SequenceOf,
    Asn1SetOf,
    Asn1Time,
    Asn1TimeOfDay,
    Asn1UniversalString,
    Asn1UtcTime,
    Asn1Utf8String,
    Asn1VisibleString,
};
