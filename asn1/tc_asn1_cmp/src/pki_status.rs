//! RFC 4210 §5.2.3 `PKIStatus`, also the status of an RFC 3161 time-stamp
//! response.
//!
//! ```text
//! PKIStatus ::= INTEGER {
//!     accepted               (0),
//!     grantedWithMods        (1),
//!     rejection              (2),
//!     waiting                (3),
//!     revocationWarning      (4),
//!     revocationNotification (5),
//!     keyUpdateWarning       (6) }
//! ```
//!
//! RFC 3161 names value 0 `granted`; Bouncy Castle follows it.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The outcome of a request.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_cmp::PkiStatus;
///
/// assert_eq!(PkiStatus::Rejection.encode_to_vec(&EncodingOptions::DER)?, [2, 1, 2]);
/// assert_eq!(PkiStatus::Granted.to_string(), "granted");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PkiStatus {
    /// `granted (0)`: exactly what was asked for; RFC 4210 calls it `accepted`.
    Granted = 0,
    /// `grantedWithMods (1)`: something like what was asked for.
    GrantedWithMods = 1,
    /// `rejection (2)`: refused; the failure information says why.
    Rejection = 2,
    /// `waiting (3)`: not yet processed.
    Waiting = 3,
    /// `revocationWarning (4)`: a revocation is imminent.
    RevocationWarning = 4,
    /// `revocationNotification (5)`: a revocation has occurred.
    RevocationNotification = 5,
    /// `keyUpdateWarning (6)`: the update was already done.
    KeyUpdateWarning = 6,
}

impl PkiStatus {
    /// Returns the INTEGER value.
    /// Variable time: branches only on the encoding structure.
    pub fn number(self) -> u8 {
        self as u8
    }

    /// Returns the named status, rejecting other values with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn from_number(number: u8) -> Result<Self, Asn1Error> {
        match number {
            0 => Ok(Self::Granted),
            1 => Ok(Self::GrantedWithMods),
            2 => Ok(Self::Rejection),
            3 => Ok(Self::Waiting),
            4 => Ok(Self::RevocationWarning),
            5 => Ok(Self::RevocationNotification),
            6 => Ok(Self::KeyUpdateWarning),
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

impl fmt::Display for PkiStatus {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Granted => "granted",
            Self::GrantedWithMods => "grantedWithMods",
            Self::Rejection => "rejection",
            Self::Waiting => "waiting",
            Self::RevocationWarning => "revocationWarning",
            Self::RevocationNotification => "revocationNotification",
            Self::KeyUpdateWarning => "keyUpdateWarning",
        })
    }
}

impl DecodeInner for PkiStatus {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, value) = Asn1Integer::decode_inner(buff, context)?;
        let number = u8::try_from(&value).map_err(|_| Asn1Error::MalformedValue)?;
        Ok((used, Self::from_number(number)?))
    }
}

impl EncodeContent for PkiStatus {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, _rules: &EncodingOptions) -> usize {
        1
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, _rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        *out.first_mut().ok_or(Asn1Error::BufferTooSmall)? = self.number();
        Ok(1)
    }
}

impl Decode for PkiStatus {}

impl Tagged for PkiStatus {
    const TAG: &'static [u8] = tag::INTEGER;
}

impl EncodeTagged for PkiStatus {}

impl Encode for PkiStatus {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
