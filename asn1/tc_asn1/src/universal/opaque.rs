//! 「只是一段位元組、不驗內容」的型別，差別只在 tag。
//!
//! GraphicString 是 ISO 2022 的字集切換機制，沒有實作能可靠驗它；ObjectDescriptor
//! 就是包一個 GraphicString。兩者 PKIX 都不用，但 X.680 有，所以照 bc 補上，存
//! 位元組不解讀。
//!
//! TeletexString、VideotexString 與 GeneralString 同樣只保存位元組；不驗證其
//! 字集，也不將內容解讀成 UTF-8。BER 與 DER 都原樣寫回內容，不正規化字集切換。

/// 生一個位元組容器型別：`new` / `as_bytes` / `From<Vec<u8>>`、雙向編解碼、基本測試。
macro_rules! opaque_bytes {
    ($name:ident, $tag:expr, $constructed_tag:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct $name {
            bytes: alloc::vec::Vec<u8>,
        }

        impl $name {
            /// Universal primitive identifier octets for this string type.
            pub const TAG: &'static [u8] = $tag;

            /// Universal constructed identifier for segmented encodings.
            pub const CONSTRUCTED_TAG: &'static [u8] = $constructed_tag;

            /// 複製位元組，不驗字集。變動時間：配置與複製量由內容長度決定。
            pub fn new(bytes: &[u8]) -> Self {
                Self {
                    bytes: bytes.to_vec(),
                }
            }

            /// 借用原始位元組。
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl From<alloc::vec::Vec<u8>> for $name {
            /// 接收既有位元組容器，不驗內容也不複製。
            fn from(bytes: alloc::vec::Vec<u8>) -> Self {
                Self { bytes }
            }
        }

        impl<'a> $crate::Decode<'a> for $name {
            fn decode(
                buff: &'a [u8],
                options: $crate::DecodingOptions,
            ) -> Result<(usize, Self), $crate::Asn1Error> {
                let element = $crate::Asn1Ref::parse(buff, options)?;
                let value = if element.is_constructed() {
                    <Self as $crate::DecodeConstructed<'a>>::decode_constructed(
                        element.value(),
                        options,
                    )?
                } else {
                    <Self as $crate::DecodeContent<'a>>::decode_content(element.value(), options)?
                };
                Ok((element.total_len(), value))
            }
        }

        impl<'a> $crate::traits::DecodeContent<'a> for $name {
            /// 任何內容都合法，包括空的。
            /// 變動時間：配置與複製量由內容長度決定。
            fn decode_content(
                value: &'a [u8],
                options: $crate::decoding_options::DecodingOptions,
            ) -> Result<Self, $crate::error::Asn1Error> {
                options.check_content_len(value.len())?;
                Ok(Self::new(value))
            }
        }

        $crate::segments::constructed_string_decode!($name);

        impl $name {
            /// 回傳內容長度。常數時間：讀取已儲存的容器長度。
            fn primitive_content_len(&self, _: &$crate::EncodingOptions) -> usize {
                self.bytes.len()
            }

            /// 原樣寫入內容。變動時間：複製量由內容長度決定。
            fn encode_primitive_content(
                &self,
                _: &$crate::EncodingOptions,
                out: &mut [u8],
            ) -> Result<usize, $crate::error::Asn1Error> {
                out[..self.bytes.len()].copy_from_slice(&self.bytes);
                Ok(self.bytes.len())
            }
        }

        impl $crate::EncodeContent for $name {
            $crate::segments::cer_string_content_encode!();
        }

        impl $crate::EncodeTagged for $name {
            $crate::segments::cer_string_encode!();
        }

        impl $crate::traits::Encode for $name {
            fn encoded_len(&self, rules: &$crate::EncodingOptions) -> usize {
                $crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
            }

            fn encode(
                &self,
                rules: &$crate::EncodingOptions,
                out: &mut [u8],
            ) -> Result<usize, $crate::Asn1Error> {
                $crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
            }
        }
    };
}

opaque_bytes!(
    Asn1GraphicString,
    super::tag::GRAPHIC_STRING,
    super::tag::CONSTRUCTED_GRAPHIC_STRING,
    "ASN.1 `GraphicString`。位元組原樣，不驗字集。"
);

opaque_bytes!(
    Asn1ObjectDescriptor,
    super::tag::OBJECT_DESCRIPTOR,
    super::tag::CONSTRUCTED_OBJECT_DESCRIPTOR,
    "ASN.1 `ObjectDescriptor`：給人看的物件描述，內容是 GraphicString。"
);

opaque_bytes!(
    Asn1TeletexString,
    super::tag::TELETEX_STRING,
    super::tag::CONSTRUCTED_TELETEX_STRING,
    r#"ASN.1 `TeletexString`。位元組原樣保存，不驗證 T.61 字集。

# Examples

內容不必是 UTF-8；編碼保留原始位元組。

```
use tc_asn1::{Asn1TeletexString, Encode, EncodingOptions, EncodingType};

let value = Asn1TeletexString::new(&[0xC1, b'e']);
let mut out = [0; 4];
value.encode(&EncodingOptions::new(EncodingType::Der), &mut out).unwrap();
assert_eq!(out, [0x14, 2, 0xC1, b'e']);
assert_eq!(value.as_bytes(), &[0xC1, b'e']);
```"#
);

opaque_bytes!(
    Asn1VideotexString,
    super::tag::VIDEOTEX_STRING,
    super::tag::CONSTRUCTED_VIDEOTEX_STRING,
    r#"ASN.1 `VideotexString`。位元組原樣保存，不驗字集。

# Examples

解碼不會移除控制位元組或拒絕非 UTF-8 內容。

```
use tc_asn1::{Asn1VideotexString, DecodingOptions, Decode};

let (used, value) = Asn1VideotexString::decode(
    &[0x15, 3, 0x1B, 0, 0xFF], DecodingOptions::default(),
).unwrap();
assert_eq!(used, 5);
assert_eq!(value.as_bytes(), &[0x1B, 0, 0xFF]);
```"#
);

opaque_bytes!(
    Asn1GeneralString,
    super::tag::GENERAL_STRING,
    super::tag::CONSTRUCTED_GENERAL_STRING,
    r#"ASN.1 `GeneralString`。位元組原樣保存，不驗字集或正規化字集切換。

# Examples

可以直接接收擁有的位元組容器，寫出時只加上此型別的標籤與長度。

```
use tc_asn1::{Asn1GeneralString, Encode, EncodingOptions, EncodingType};

let value = Asn1GeneralString::from(vec![0, 0xFF]);
let mut out = [0; 4];
value.encode(&EncodingOptions::new(EncodingType::Ber(tc_asn1::LengthForm::Definite)), &mut out).unwrap();
assert_eq!(out, [0x1B, 2, 0, 0xFF]);
```"#
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EncodeContent;
    use crate::decoding_options::DecodingOptions;
    use crate::error::Asn1Error;
    use crate::traits::{Decode, Encode};
    use crate::{EncodingOptions, EncodingType};

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT, 16 * 1024 * 1024, 65_536);

    macro_rules! opaque_string_tests {
        ($module:ident, $name:ident, $tag:expr) => {
            mod $module {
                use super::*;
                use alloc::vec;
                use alloc::vec::Vec;

                #[test]
                fn ordinary_contents_round_trip_under_both_encoding_rules() {
                    let value = $name::new(b"ABC");
                    for rules in [
                        &EncodingOptions::new(EncodingType::Ber(crate::LengthForm::Definite)),
                        &EncodingOptions::new(EncodingType::Der),
                    ] {
                        let mut out = [0; 5];
                        assert_eq!(value.encode(rules, &mut out), Ok(5));
                        assert_eq!(out, [$tag, 3, b'A', b'B', b'C']);
                        assert_eq!(value.content_len(rules), 3);
                        assert_eq!($name::decode(&out, OPTIONS), Ok((5, value.clone())));
                    }
                }

                #[test]
                fn every_byte_value_is_preserved_without_charset_validation() {
                    let bytes: Vec<u8> = (0..=u8::MAX).collect();
                    let value = $name::from(bytes.clone());
                    assert_eq!(value.as_bytes(), bytes.as_slice());
                    for rules in [
                        &EncodingOptions::new(EncodingType::Ber(crate::LengthForm::Definite)),
                        &EncodingOptions::new(EncodingType::Der),
                    ] {
                        let mut out = vec![0; value.encoded_len(rules)];
                        assert_eq!(value.encode(rules, &mut out), Ok(out.len()));
                        assert_eq!(&out[..4], &[$tag, 0x82, 1, 0]);
                        assert_eq!(&out[4..], bytes.as_slice());
                        let (used, decoded) = $name::decode(&out, OPTIONS).unwrap();
                        assert_eq!(used, out.len());
                        assert_eq!(decoded, value);
                    }
                }

                #[test]
                fn empty_contents_are_valid_and_encode_with_zero_length() {
                    let value = $name::new(&[]);
                    assert_eq!(value, $name::default());
                    assert_eq!(value.as_bytes(), &[]);
                    let mut out = [0; 2];
                    assert_eq!(
                        value.encode(&EncodingOptions::new(EncodingType::Der), &mut out),
                        Ok(2)
                    );
                    assert_eq!(out, [$tag, 0]);
                    assert_eq!($name::decode(&out, OPTIONS), Ok((2, value)));
                }

                #[test]
                fn the_schema_checks_tags_an_octet_string_tag_is_rejected_even_with_valid_contents()
                {
                    assert_eq!(
                        crate::Fields::new(&[4, 1, b'A'], OPTIONS)
                            .and_then(|mut fields| fields.required::<$name>(&[$tag])),
                        Err(Asn1Error::UnexpectedTag)
                    );
                }
            }
        };
    }

    opaque_string_tests!(teletex_string, Asn1TeletexString, 0x14);
    opaque_string_tests!(videotex_string, Asn1VideotexString, 0x15);
    opaque_string_tests!(general_string, Asn1GeneralString, 0x1B);

    #[test]
    fn graphic_string_and_object_descriptor_pass_bytes_through_untouched() {
        let mut out = [0_u8; 8];

        let (used, s) = Asn1GraphicString::decode(&[0x19, 0x02, 0xDE, 0xAD], OPTIONS).unwrap();
        assert_eq!((used, s.as_bytes()), (4, &[0xDE, 0xAD][..]));
        assert_eq!(
            s.encode(&EncodingOptions::new(EncodingType::Der), &mut out)
                .unwrap(),
            4
        );
        assert_eq!(&out[..4], &[0x19, 0x02, 0xDE, 0xAD]);

        let (used, d) = Asn1ObjectDescriptor::decode(&[0x07, 0x01, b'x'], OPTIONS).unwrap();
        assert_eq!((used, d.as_bytes()), (3, &b"x"[..]));
        assert_eq!(
            d.encode(&EncodingOptions::new(EncodingType::Der), &mut out)
                .unwrap(),
            3
        );
        assert_eq!(&out[..3], &[0x07, 0x01, b'x']);
    }

    #[test]
    fn the_schema_checks_tags_the_two_tags_are_not_interchangeable() {
        assert_eq!(
            crate::Fields::new(&[0x07, 0x00], OPTIONS)
                .and_then(
                    |mut fields| fields.required::<Asn1GraphicString>(crate::tag::GRAPHIC_STRING)
                ),
            Err(Asn1Error::UnexpectedTag)
        );
        assert_eq!(
            crate::Fields::new(&[0x19, 0x00], OPTIONS)
                .and_then(|mut fields| fields
                    .required::<Asn1ObjectDescriptor>(crate::tag::OBJECT_DESCRIPTOR)),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
