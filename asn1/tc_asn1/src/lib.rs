#![no_std]

extern crate alloc;

mod asn1_any;
// mod asn1_object;
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
// pub use asn1_object::{Asn1Object, Asn1Tagged, TaggedContent};
pub use asn1_ref::{Asn1Class, Asn1Ref, Children};
pub use decoding_context::DecodingContext;
pub use decoding_options::DecodingOptions;
pub use encoding_options::EncodingOptions;
pub use encoding_type::{EncodingType, LengthForm};
pub use error::Asn1Error;
//pub use schema::{Explicit, Fields, Implicit, SequenceFields};
pub use traits::{
    Decode, DecodeConstructed, DecodeContent, DecodeInner, Encode, EncodeContent, EncodeTagged,
};
pub use universal::tag;
pub use universal::{
    Arcs,
    Asn1BitString,
    //Asn1BitStringConstructed,
    Asn1BmpString,
    Asn1Boolean,
    //Asn1CharacterString, Asn1Date, Asn1DateTime,
    //     Asn1Duration, Asn1EmbeddedPdv,
    Asn1Enumerated,
    //     Asn1External, Asn1GeneralString,
    //     Asn1GeneralizedTime, Asn1GraphicString,
    Asn1Ia5String,
    //Asn1Ia5StringConstructed,
    Asn1Integer,
    Asn1Null,
    Asn1NumericString,
    //Asn1NumericStringConstructed,
    //     Asn1ObjectDescriptor,
    Asn1OctetString,
    //Asn1OctetStringConstructed,
    Asn1Oid,
    //Asn1OidIri,
    Asn1PrintableString,
    //Asn1PrintableStringConstructed,
    //     Asn1Real,
    Asn1RelativeOid,
    //Asn1RelativeOidIri, Asn1SequenceOf, Asn1SetOf,
    //     Asn1TeletexString, Asn1Time, Asn1TimeOfDay, Asn1UniversalString, Asn1UtcTime,
    Asn1Utf8String,
    //     Asn1VideotexString,
    Asn1VisibleString,
    //     ExternalEncoding, PdvIdentification,
};
