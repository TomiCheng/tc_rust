//! What an encoder is told about the form to produce.

use crate::EncodingType;

/// The choices an encoding is made under, passed to every
/// [`Encode`](crate::Encode) and [`EncodeContent`](crate::EncodeContent)
/// call so that nested values follow the same rules as the outer one.
///
/// Today this is the [`EncodingType`] alone; it is a struct so that later
/// options (a segment size, say) do not change every signature. The values
/// of the struct are pure choices, never limits: an encoder writes whatever
/// it is given.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1SetOf, Asn1Integer, Encode, EncodingOptions, EncodingType, LengthForm};
///
/// let set = Asn1SetOf::new(vec![Asn1Integer::from(2), Asn1Integer::from(1)]);
///
/// // DER sorts the SET OF; plain BER writes the elements as given.
/// let der = set.encode_to_vec(&EncodingOptions::new(EncodingType::Der))?;
/// assert_eq!(der, [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
/// let ber = set.encode_to_vec(&EncodingOptions::new(EncodingType::Ber(LengthForm::Definite)))?;
/// assert_eq!(ber, [0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01]);
///
/// // Indefinite BER wraps the constructed value in `80 ... 00 00`.
/// let indefinite = set.encode_to_vec(&EncodingOptions::new(EncodingType::Ber(LengthForm::Indefinite)))?;
/// assert_eq!(indefinite, [0x31, 0x80, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x00, 0x00]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodingOptions {
    encoding_type: EncodingType,
}

impl EncodingOptions {
    pub const fn new(encoding_type: EncodingType) -> Self {
        Self { encoding_type }
    }

    pub const fn encoding_type(&self) -> EncodingType {
        self.encoding_type
    }

    /// [`EncodingType::is_canonical`] of the chosen rules.
    pub const fn is_canonical(&self) -> bool {
        self.encoding_type.is_canonical()
    }
}
