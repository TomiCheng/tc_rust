//! RFC 5280 §4.1.2.5 `Time`.
//!
//! ```text
//! Time ::= CHOICE {
//!     utcTime        UTCTime,
//!     generalTime    GeneralizedTime
//! }
//! ```
//!
//! Dates through 2049 MUST use UTCTime and dates from 2050 on MUST use
//! GeneralizedTime; [`Time::new`] picks the alternative by year.

use core::{cmp::Ordering, fmt};

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ref, Asn1UtcTime, Decode, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions,
};

/// A CHOICE between the two time types, so it has no single identifier.
/// Ordering is chronological whichever alternative carries the instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Time {
    UtcTime(Asn1UtcTime),
    GeneralizedTime(Asn1GeneralizedTime),
}

impl Time {
    /// Picks the alternative RFC 5280 requires for the year: UTCTime through
    /// 2049, GeneralizedTime from 2050. Fields are validated like the two types.
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, Asn1Error> {
        if year <= 2049 {
            Asn1UtcTime::new(year, month, day, hour, minute, second).map(Self::UtcTime)
        } else {
            Asn1GeneralizedTime::new(year, month, day, hour, minute, second)
                .map(Self::GeneralizedTime)
        }
    }

    pub fn year(&self) -> u16 {
        match self {
            Self::UtcTime(t) => t.year(),
            Self::GeneralizedTime(t) => t.year(),
        }
    }
    pub fn month(&self) -> u8 {
        match self {
            Self::UtcTime(t) => t.month(),
            Self::GeneralizedTime(t) => t.month(),
        }
    }
    pub fn day(&self) -> u8 {
        match self {
            Self::UtcTime(t) => t.day(),
            Self::GeneralizedTime(t) => t.day(),
        }
    }
    pub fn hour(&self) -> u8 {
        match self {
            Self::UtcTime(t) => t.hour(),
            Self::GeneralizedTime(t) => t.hour(),
        }
    }
    pub fn minute(&self) -> u8 {
        match self {
            Self::UtcTime(t) => t.minute(),
            Self::GeneralizedTime(t) => t.minute(),
        }
    }
    pub fn second(&self) -> u8 {
        match self {
            Self::UtcTime(t) => t.second(),
            Self::GeneralizedTime(t) => t.second(),
        }
    }

    fn sort_key(&self) -> (u16, u8, u8, u8, u8, u8, u8) {
        let alternative = match self {
            Self::UtcTime(_) => 0,
            Self::GeneralizedTime(_) => 1,
        };
        (
            self.year(),
            self.month(),
            self.day(),
            self.hour(),
            self.minute(),
            self.second(),
            alternative,
        )
    }
}

impl Ord for Time {
    /// Compares the instants, so a GeneralizedTime before 2050 still sorts
    /// before a later UTCTime. The same instant in the two alternatives puts
    /// UTCTime first, keeping the order consistent with `Eq`. Variable time:
    /// branches on the fields, which are public.
    fn cmp(&self, other: &Self) -> Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

impl PartialOrd for Time {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<Asn1UtcTime> for Time {
    fn from(value: Asn1UtcTime) -> Self {
        Self::UtcTime(value)
    }
}

impl From<Asn1GeneralizedTime> for Time {
    fn from(value: Asn1GeneralizedTime) -> Self {
        Self::GeneralizedTime(value)
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UtcTime(t) => t.fmt(f),
            Self::GeneralizedTime(t) => t.fmt(f),
        }
    }
}

impl DecodeInner for Time {
    /// The identifier selects the alternative. Variable time: branches only on the tag.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        if element.tag() == Asn1UtcTime::TAG {
            let (used, value) = Asn1UtcTime::decode_inner(buff, context)?;
            Ok((used, Self::UtcTime(value)))
        } else if element.tag() == Asn1GeneralizedTime::TAG {
            let (used, value) = Asn1GeneralizedTime::decode_inner(buff, context)?;
            Ok((used, Self::GeneralizedTime(value)))
        } else {
            Err(Asn1Error::UnexpectedTag)
        }
    }
}

impl Decode for Time {}

impl EncodeContent for Time {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::UtcTime(t) => t.content_len(rules),
            Self::GeneralizedTime(t) => t.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::UtcTime(t) => t.encode_content(rules, out),
            Self::GeneralizedTime(t) => t.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for Time {}

/// Each alternative writes its own identifier.
impl Encode for Time {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::UtcTime(t) => t.encoded_len(rules),
            Self::GeneralizedTime(t) => t.encoded_len(rules),
        }
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::UtcTime(t) => t.encode(rules, out),
            Self::GeneralizedTime(t) => t.encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use core::cmp::Ordering;

    use tc_asn1::{
        Asn1Error, Asn1GeneralizedTime, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::Time;

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    #[test]
    fn the_year_selects_utctime_through_2049_and_generalizedtime_from_2050() {
        let t = Time::new(2049, 12, 31, 23, 59, 59).unwrap();
        assert!(matches!(t, Time::UtcTime(_)));
        assert_eq!(t.encode_to_vec(&der()).unwrap(), b"\x17\x0d491231235959Z");
        let t = Time::new(2050, 1, 1, 0, 0, 0).unwrap();
        assert!(matches!(t, Time::GeneralizedTime(_)));
        assert_eq!(t.encode_to_vec(&der()).unwrap(), b"\x18\x0f20500101000000Z");
    }

    #[test]
    fn decoding_follows_the_identifier_and_rejects_other_tags() {
        let (used, t) =
            Time::decode(b"\x17\x0d260918123456Z", &DecodingOptions::default()).unwrap();
        assert_eq!((used, t.to_string().as_str()), (15, "2026-09-18T12:34:56Z"));
        let (_, t) = Time::decode(b"\x18\x0f20600101000000Z", &DecodingOptions::default()).unwrap();
        assert_eq!(t.year(), 2060);
        assert!(matches!(
            Time::decode(b"\x13\x0d260918123456Z", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn times_order_across_the_two_alternatives() {
        assert!(
            Time::new(2049, 12, 31, 23, 59, 59).unwrap() < Time::new(2050, 1, 1, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn a_generalizedtime_before_2050_orders_by_its_instant_not_its_alternative() {
        let early = Time::GeneralizedTime(Asn1GeneralizedTime::new(2020, 1, 1, 0, 0, 0).unwrap());
        let late = Time::new(2030, 1, 1, 0, 0, 0).unwrap();
        assert!(early < late);
        assert!(late > early);
    }

    #[test]
    fn the_same_instant_in_both_alternatives_differs_and_puts_utctime_first() {
        let utc = Time::new(2026, 1, 1, 0, 0, 0).unwrap();
        let general = Time::GeneralizedTime(Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0).unwrap());
        assert_ne!(utc, general);
        assert_eq!(utc.cmp(&general), Ordering::Less);
    }
}
