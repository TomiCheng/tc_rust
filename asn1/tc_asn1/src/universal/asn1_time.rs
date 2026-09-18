//! X.680 §38: TIME and the four useful time types.
//!
//! Constructors take the value notation with separators; `as_str` returns the
//! normalized notation. X.690 §8.26 strips the separators from DATE,
//! TIME-OF-DAY and DATE-TIME on the wire and the leading `P` from DURATION;
//! TIME is written as is. BER and DER both write the §11.9 canonical form.
//! Validation covers the Gregorian calendar, week numbers, precision, UTC
//! offsets and component structure; it consults no leap-second table or
//! time-zone database and does not order interval endpoints. Whether a second
//! of 60 is real is left to the caller.

use alloc::{format, string::String};
use core::fmt;

use super::{tag, time_value};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions,
};

#[derive(Clone, Copy)]
enum Kind {
    Time,
    Date,
    Clock,
    DateTime,
    Duration,
}

impl Kind {
    fn validate(self, text: &str) -> Result<String, Asn1Error> {
        match self {
            Self::Time => time_value::time(text),
            Self::Date => time_value::useful_date(text),
            Self::Clock => time_value::useful_clock(text),
            Self::DateTime => time_value::useful_date_time(text),
            Self::Duration => time_value::duration(text),
        }
    }

    /// The contents octets: the notation without separators (or without `P`).
    fn wire(self, text: &str) -> String {
        match self {
            Self::Time => String::from(text),
            Self::Duration => String::from(&text[1..]),
            _ => text
                .chars()
                .filter(|c| !matches!(c, '-' | ':' | 'T'))
                .collect(),
        }
    }

    /// The notation rebuilt from the contents octets, separators restored.
    fn notation(self, wire: &str) -> Result<String, Asn1Error> {
        if matches!(self, Self::Time) {
            return Ok(String::from(wire));
        }
        if matches!(self, Self::Duration) {
            return Ok(format!("P{wire}"));
        }
        let len = match self {
            Self::Date => 8,
            Self::Clock => 6,
            _ => 14,
        };
        if wire.len() != len || !wire.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(match self {
            Self::Date => format!("{}-{}-{}", &wire[..4], &wire[4..6], &wire[6..]),
            Self::Clock => format!("{}:{}:{}", &wire[..2], &wire[2..4], &wire[4..]),
            _ => format!(
                "{}-{}-{}T{}:{}:{}",
                &wire[..4],
                &wire[4..6],
                &wire[6..8],
                &wire[8..10],
                &wire[10..12],
                &wire[12..]
            ),
        })
    }
}

/// The five types differ only in tag, validator and separator rule.
macro_rules! time_type {
    ($name:ident, $tag:ident, $kind:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        pub struct $name {
            text: String,
            wire: String,
        }

        impl $name {
            pub const TAG: &'static [u8] = tag::$tag;

            /// Validates and normalizes the value notation; invalid structure or
            /// values are [`Asn1Error::MalformedValue`].
            /// Variable time: branches on the components, digits and length.
            pub fn new(text: &str) -> Result<Self, Asn1Error> {
                let text = Kind::$kind.validate(text)?;
                let wire = Kind::$kind.wire(&text);
                Ok(Self { text, wire })
            }

            /// The normalized notation with separators; not the wire contents.
            pub fn as_str(&self) -> &str {
                &self.text
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.text)
            }
        }

        impl DecodeInner for $name {
            fn decode_inner(
                buff: &[u8],
                context: &mut DecodingContext,
            ) -> Result<(usize, Self), Asn1Error> {
                let element = crate::Asn1Ref::parse(buff, context)?;
                if element.tag() != Self::TAG {
                    return Err(Asn1Error::UnexpectedTag);
                }
                let value = Self::decode_content(element.value(), context)?;
                Ok((element.total_len(), value))
            }
        }

        impl Decode for $name {}

        impl DecodeContent for $name {
            /// Restores the notation from the wire contents, then validates and
            /// normalizes it. Variable time: branches on the contents.
            fn decode_content(
                value: &[u8],
                context: &mut DecodingContext,
            ) -> Result<Self, Asn1Error> {
                context.options().check_content_len(value.len())?;
                let wire = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
                let decoded = Self::new(&Kind::$kind.notation(wire)?)?;
                // DER contents are the §11.9 canonical form, which is what the
                // value stores: anything else re-encodes differently.
                if context.is_der() && decoded.wire.as_bytes() != value {
                    return Err(Asn1Error::NotDer);
                }
                Ok(decoded)
            }
        }

        impl EncodeContent for $name {
            fn content_len(&self, _: &EncodingOptions) -> usize {
                self.wire.len()
            }

            fn encode_content(
                &self,
                _: &EncodingOptions,
                out: &mut [u8],
            ) -> Result<usize, Asn1Error> {
                let out = out
                    .get_mut(..self.wire.len())
                    .ok_or(Asn1Error::BufferTooSmall)?;
                out.copy_from_slice(self.wire.as_bytes());
                Ok(self.wire.len())
            }
        }

        impl EncodeTagged for $name {}

        impl Encode for $name {
            fn encoded_len(&self, rules: &EncodingOptions) -> usize {
                self.encoded_len_tagged(Self::TAG, rules)
            }

            fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
                self.encode_tagged(Self::TAG, rules, out)
            }
        }
    };
}

time_type!(
    Asn1Time,
    TIME,
    Time,
    r#"TIME: a date, time, interval, duration or recurring interval.

Equality compares the normalized notation, so precision, UTC offset and the
date representation are significant; no conversion across time zones. The
calendar and component structure are validated; leap-second tables are not
consulted and interval endpoints are not ordered.

# Examples

```
use tc_asn1::Asn1Time;
let interval = Asn1Time::new("R3/2024-01-01T12:30+08:00/2024-01-02T12:30+08").unwrap();
assert_eq!(interval.as_str(), "R3/2024-01-01T12:30+08/2024-01-02T12:30");
```"#
);
time_type!(
    Asn1Date,
    DATE,
    Date,
    r#"DATE: a Gregorian date in 1582-9999, written `YYYY-MM-DD`.

# Examples

```
use tc_asn1::{Asn1Date, Encode, EncodingOptions, EncodingType};
let date = Asn1Date::new("2024-02-29").unwrap();
let mut out = [0; 11];
date.encode(&EncodingOptions::new(EncodingType::Der), &mut out).unwrap();
assert_eq!(&out[..3], &[0x1f, 0x1f, 8]);
assert_eq!(&out[3..], b"20240229");
assert!(Asn1Date::new("2023-02-29").is_err());
```"#
);
time_type!(
    Asn1TimeOfDay,
    TIME_OF_DAY,
    Clock,
    r#"TIME-OF-DAY: `hh:mm:ss` without zone or fraction; end-of-day `24:00:00` is allowed.

# Examples

```
use tc_asn1::Asn1TimeOfDay;
assert!(Asn1TimeOfDay::new("24:00:00").is_ok());
assert!(Asn1TimeOfDay::new("24:00:01").is_err());
assert!(Asn1TimeOfDay::new("12:00:00Z").is_err());
```"#
);
time_type!(
    Asn1DateTime,
    DATE_TIME,
    DateTime,
    r#"DATE-TIME: `YYYY-MM-DDThh:mm:ss`, year 1582-9999, without zone or fraction.

# Examples

```
use tc_asn1::Asn1DateTime;
let value = Asn1DateTime::new("2024-02-29T24:00:00").unwrap();
assert_eq!(value.as_str(), "2024-02-29T24:00:00");
assert!(Asn1DateTime::new("2024-02-30T12:00:00").is_err());
```"#
);
time_type!(
    Asn1Duration,
    DURATION,
    Duration,
    r#"DURATION: a `P`-prefixed duration; months are not converted to days.

The last component carries the precision, so a zero there is kept; other zero
components are dropped per the DER rules.

# Examples

```
use tc_asn1::Asn1Duration;
let duration = Asn1Duration::new("P0Y2M0DT0,00S").unwrap();
assert_eq!(duration.as_str(), "P2MT0.00S");
assert_ne!(duration, Asn1Duration::new("P2M").unwrap());
```"#
);
