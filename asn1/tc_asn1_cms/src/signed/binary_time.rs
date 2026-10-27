//! RFC 6019 `BinaryTime`, a signing time as a count of seconds.
//!
//! ```text
//! BinaryTime ::= INTEGER (0..MAX)
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

/// Seconds since 1970-01-01T00:00:00Z, without leap seconds; negative values are
/// `MalformedValue`.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::signed::BinaryTime;
///
/// let time = BinaryTime::from(1_792_800_000u64);
/// let der = time.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(BinaryTime::decode_der(&der, &DecodingOptions::default())?.1, time);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct BinaryTime {
    seconds: Asn1Integer,
}

impl BinaryTime {
    /// Rejects a negative count with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(seconds: Asn1Integer) -> Result<Self, Asn1Error> {
        if seconds.is_negative() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { seconds })
    }

    /// Returns the count of seconds, which may exceed any primitive integer.
    /// Variable time: branches only on the encoding structure.
    pub fn seconds(&self) -> &Asn1Integer {
        &self.seconds
    }
}

impl From<u64> for BinaryTime {
    /// Variable time: branches only on the encoding structure.
    fn from(seconds: u64) -> Self {
        Self {
            seconds: seconds.into(),
        }
    }
}

impl DecodeInner for BinaryTime {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, seconds) = Asn1Integer::decode_inner(buff, context)?;
        Ok((len, Self::new(seconds)?))
    }
}

impl DecodeContent for BinaryTime {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        Self::new(Asn1Integer::decode_content(value, context)?)
    }
}

impl EncodeContent for BinaryTime {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.seconds.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.seconds.encode_content(rules, out)
    }
}

impl Decode for BinaryTime {}

impl Tagged for BinaryTime {
    const TAG: &'static [u8] = <Asn1Integer as Tagged>::TAG;
}

impl EncodeTagged for BinaryTime {}

impl Encode for BinaryTime {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::BinaryTime;

    #[test]
    fn the_count_is_a_bare_non_negative_integer() {
        let time = BinaryTime::from(0x80u64);
        assert_eq!(
            time.encode_to_vec(&EncodingOptions::DER).unwrap(),
            [0x02, 0x02, 0x00, 0x80]
        );
        assert_eq!(
            BinaryTime::new(Asn1Integer::from(-1)),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            BinaryTime::decode_der(&[0x02, 0x01, 0xff], &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }
}
