//! ASN.1 `NumericString`：只接受數字與空白。

use alloc::string::String;

use crate::decoding_options::DecodingOptions;
use crate::encoding_options::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

/// 內容只含 ASCII 數字 `0`–`9` 與空白，因此可以直接借用為字串。
///
/// # Examples
///
/// 空白可用來分組，但正負號不屬於 NumericString 字集。
///
/// ```
/// use tc_asn1::{Asn1NumericString, Asn1Error};
///
/// let value = Asn1NumericString::new("012 3456789").unwrap();
/// assert_eq!(value.as_str(), "012 3456789");
/// assert_eq!(Asn1NumericString::new("+123"), Err(Asn1Error::MalformedValue));
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1NumericString {
    text: String,
}

impl Asn1NumericString {
    /// Universal identifier octets for this type's default encoding form.
    pub const TAG: &'static [u8] = super::tag::NUMERIC_STRING;

    /// Universal constructed identifier for segmented encodings.
    pub const CONSTRUCTED_TAG: &'static [u8] = super::tag::CONSTRUCTED_NUMERIC_STRING;

    /// 驗證字集並複製內容；不合法時回傳 [`Asn1Error::MalformedValue`]。
    /// 變動時間：依內容長度與遇到的字元決定掃描量。
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b' ')
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            text: String::from(text),
        })
    }

    /// 借用已驗證的字串。
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl<'a> crate::Decode<'a> for Asn1NumericString {
    fn try_decode(
        buff: &'a [u8],
        options: crate::DecodingOptions,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, options)?;
        let value = if element.is_constructed() {
            <Self as crate::DecodeConstructed<'a>>::try_decode_constructed(
                element.value(),
                options,
            )?
        } else {
            <Self as crate::DecodeContent<'a>>::try_decode_content(element.value(), options)?
        };
        Ok((element.total_len(), value))
    }
}

impl<'a> DecodeContent<'a> for Asn1NumericString {
    /// 以建構時相同的字集規則驗證內容。
    /// 變動時間：依內容長度與字元分支。
    fn try_decode_content(value: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error> {
        options.check_content_len(value.len())?;
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Self::new(text)
    }
}

crate::segments::constructed_string_decode!(Asn1NumericString);

impl Asn1NumericString {
    /// 回傳內容長度。常數時間：讀取已儲存的字串長度。
    fn primitive_content_len(&self, _: EncodingOptions) -> usize {
        self.text.len()
    }

    /// 原樣寫入已驗證的內容。變動時間：複製量由內容長度決定。
    fn encode_primitive_content(
        &self,
        _: EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        out[..self.text.len()].copy_from_slice(self.text.as_bytes());
        Ok(self.text.len())
    }
}

impl crate::EncodeContent for Asn1NumericString {
    crate::segments::cer_string_content_encode!();
}

impl crate::EncodeTagged for Asn1NumericString {
    crate::segments::cer_string_encode!();
}

impl Encode for Asn1NumericString {
    fn encoded_len(&self, rules: EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decode;
    use crate::EncodeContent;

    #[test]
    fn digits_and_spaces_round_trip_under_both_encoding_rules() {
        let text = "012 3456789";
        let value = Asn1NumericString::new(text).unwrap();
        for rules in [
            EncodingOptions::Ber(crate::LengthForm::Definite),
            EncodingOptions::Der,
        ] {
            let mut out = [0; 13];
            assert_eq!(value.encode(rules, &mut out), Ok(out.len()));
            assert_eq!(&out[..2], &[0x12, 11]);
            assert_eq!(&out[2..], text.as_bytes());
            assert_eq!(value.content_len(rules), 11);
            let (used, decoded) =
                Asn1NumericString::try_decode(&out, DecodingOptions::default()).unwrap();
            assert_eq!(used, out.len());
            assert_eq!(decoded, value);
            assert_eq!(decoded.as_str(), text);
        }
    }

    #[test]
    fn construction_and_decoding_reject_characters_outside_the_numeric_alphabet() {
        for text in ["+1", "-1", "a", "1\t2", "１２", "\0"] {
            assert_eq!(Asn1NumericString::new(text), Err(Asn1Error::MalformedValue));
            assert_eq!(
                Asn1NumericString::try_decode_content(text.as_bytes(), DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
        assert_eq!(
            Asn1NumericString::try_decode_content(&[0xFF], DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn an_empty_numeric_string_is_valid_and_encodes_with_zero_length() {
        let value = Asn1NumericString::new("").unwrap();
        assert_eq!(value, Asn1NumericString::default());
        assert_eq!(value.as_str(), "");
        let mut out = [0; 2];
        assert_eq!(value.encode(EncodingOptions::Der, &mut out), Ok(2));
        assert_eq!(out, [0x12, 0]);
        assert_eq!(
            Asn1NumericString::try_decode(&out, DecodingOptions::default()),
            Ok((2, value))
        );
    }

    #[test]
    fn the_schema_checks_tags_a_numeric_string_rejects_an_ia5_string_tag() {
        assert_eq!(
            crate::Fields::new(&[0x16, 1, b'1'], DecodingOptions::default())
                .and_then(|mut fields| fields.required::<Asn1NumericString>(Asn1NumericString::TAG)),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
