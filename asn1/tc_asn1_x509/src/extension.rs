//! RFC 5280 §4.1 的 `Extension`。
//!
//! ```text
//! Extension ::= SEQUENCE {
//!     extnID     OBJECT IDENTIFIER,
//!     critical   BOOLEAN DEFAULT FALSE,
//!     extnValue  OCTET STRING   -- 裡面是另一個值的 DER，型別看 extnID
//! }
//! ```
//!
//! 兩件事第一次出現在這裡：**DEFAULT**（X.690 11.5：DER 下等於預設值就不寫，所以
//! `critical` 為 false 時整個欄位不存在），以及**OCTET STRING 包 DER**（殼要先剝，
//! 裡面的型別由 `extnID` 決定）。

use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1OctetString, Asn1Oid, Decode, DecodeContent, DecodingOptions,
    Encode, EncodingOptions, Fields, SequenceFields,
};

/// 一個 X.509 extension。
///
/// # 範例
///
/// ```
/// use tc_asn1::{Asn1Boolean, Asn1SequenceOf, DecodingOptions, Encode, EncodingOptions, EncodingType, Decode};
/// use tc_asn1_x509::Extension;
///
/// // basicConstraints，critical，內容是 SEQUENCE { cA TRUE }
/// let bytes = [
///     0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF,
///     0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF,
/// ];
/// let (used, ext) = Extension::try_decode(&bytes, DecodingOptions::default())?;
/// assert_eq!(used, bytes.len());
/// assert_eq!(ext.extn_id().to_string(), "2.5.29.19");
/// assert!(ext.critical());
///
/// // 殼裡的東西：知道 2.5.29.19 是 BasicConstraints 才這樣解
/// let inner = ext.extn_value_as::<Asn1SequenceOf<Asn1Boolean>>(DecodingOptions::default())?;
/// assert_eq!(inner.members(), &[Asn1Boolean::from(true)]);
///
/// // 重編回原位元組
/// let mut out = vec![0_u8; ext.encoded_len(&EncodingOptions::new(EncodingType::Der))];
/// ext.encode(&EncodingOptions::new(EncodingType::Der), &mut out)?;
/// assert_eq!(out, bytes);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
///
/// # 時間性質
///
/// 變動時間。分支只依編碼結構；extension 是憑證的公開內容。
#[derive(Debug)]
pub struct Extension {
    extn_id: Asn1Oid,
    critical: bool,
    extn_value: Asn1OctetString,
}

impl Extension {
    /// `extn_value` 是**已經編好**的內層 DER；呼叫端先把內層值 `encode` 好再放進來。
    pub fn new(extn_id: Asn1Oid, critical: bool, extn_value: &[u8]) -> Self {
        Self {
            extn_id,
            critical,
            extn_value: Asn1OctetString::new(extn_value),
        }
    }

    pub fn extn_id(&self) -> &Asn1Oid {
        &self.extn_id
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    /// 殼裡的 DER，還沒解。
    pub fn extn_value(&self) -> &[u8] {
        self.extn_value.as_bytes()
    }

    /// 剝掉 OCTET STRING 的殼，把裡面的 DER 解成 `T`。要求剛好用完。
    ///
    /// `T` 由 `extn_id` 決定 —— 這個型別不知道對應表，呼叫端知道。
    /// 變動時間：分支只依編碼結構；此處只驗證完整消耗，不驗證 DER 正規形式。
    pub fn extn_value_as<'a, T: Decode<'a>>(
        &'a self,
        options: DecodingOptions,
    ) -> Result<T, Asn1Error> {
        let (used, value) = T::try_decode(self.extn_value.as_bytes(), options)?;
        if used != self.extn_value.as_bytes().len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }
}

impl<'a> tc_asn1::Decode<'a> for Extension {
    fn try_decode(
        buff: &'a [u8],
        options: tc_asn1::DecodingOptions,
    ) -> Result<(usize, Self), tc_asn1::Asn1Error> {
        let element = tc_asn1::Asn1Ref::parse(buff, options)?;
        if !element.is_constructed() {
            return Err(tc_asn1::Asn1Error::UnexpectedTag);
        }
        let value =
            <Self as tc_asn1::DecodeContent<'a>>::try_decode_content(element.value(), options)?;
        Ok((element.total_len(), value))
    }
}

impl<'a> DecodeContent<'a> for Extension {
    /// 變動時間：分支只依編碼結構。
    ///
    /// `critical` 是 DEFAULT FALSE：第二個子元素的 tag 是 BOOLEAN 就是它，否則
    /// 視為省略。明寫 `FALSE` 不是 DER，但寬鬆接受；重編時會消失。
    fn try_decode_content(value: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error> {
        let mut fields = Fields::new(value, options)?;
        let extn_id = fields.required(tc_asn1::tag::OBJECT_IDENTIFIER)?;
        let critical = fields
            .default(tc_asn1::tag::BOOLEAN, Asn1Boolean::from(false))?
            .is_true();
        let value_tag = fields.peek()?.ok_or(Asn1Error::Truncated)?.tag();
        if value_tag != tc_asn1::tag::OCTET_STRING
            && value_tag != tc_asn1::tag::CONSTRUCTED_OCTET_STRING
        {
            return Err(Asn1Error::UnexpectedTag);
        }
        let extn_value = fields.required(value_tag)?;
        fields.finish()?;
        Ok(Self {
            extn_id,
            critical,
            extn_value,
        })
    }
}

impl SequenceFields for Extension {
    /// 變動時間：分支只依編碼結構。
    fn fields(&self, _: &EncodingOptions, sink: &mut dyn FnMut(&dyn Encode)) {
        sink(&self.extn_id);
        if self.critical {
            sink(&Asn1Boolean::from(true));
        }
        sink(&self.extn_value);
    }
}

tc_asn1::impl_sequence_encode!(Extension);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use tc_asn1::EncodingType;

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(tc_asn1::Depth::DEFAULT, 16 * 1024 * 1024, 65_536);

    #[test]
    fn long_extension_values_round_trip_through_generic_cer_fields_and_keep_der_bytes() {
        let value = Extension::new("2.5.29.14".parse().unwrap(), false, &[0xaa; 1001]);
        let mut cer = alloc::vec![
            0x30, 0x80, 6, 3, 0x55, 0x1d, 0x0e, 0x24, 0x80, 4, 0x82, 3, 0xe8
        ];
        cer.extend_from_slice(&[0xaa; 1000]);
        cer.extend_from_slice(&[4, 1, 0xaa, 0, 0, 0, 0]);
        assert_eq!(
            value.encoded_len(&EncodingOptions::new(EncodingType::Cer)),
            cer.len()
        );
        assert_eq!(
            value
                .encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
                .unwrap(),
            cer
        );
        let decoded = Extension::try_decode(&cer, OPTIONS)
            .map(|(_, value)| value)
            .unwrap();
        assert_eq!(decoded.extn_id(), value.extn_id());
        assert_eq!(decoded.critical(), value.critical());
        assert_eq!(decoded.extn_value(), value.extn_value());
        assert_eq!(
            decoded
                .encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
                .unwrap(),
            cer
        );
        assert!(matches!(
            {
                let input: &[u8] = &cer;
                Extension::try_decode(input, OPTIONS).and_then(|(used, value)| {
                    if used != input.len() {
                        Err(tc_asn1::Asn1Error::TrailingData)
                    } else if value
                        .encode_to_vec(&tc_asn1::EncodingOptions::new(tc_asn1::EncodingType::Der))?
                        != input
                    {
                        Err(tc_asn1::Asn1Error::NotDer)
                    } else {
                        Ok(value)
                    }
                })
            },
            Err(Asn1Error::NotDer)
        ));
        let mut der = alloc::vec![
            0x30, 0x82, 3, 0xf2, 6, 3, 0x55, 0x1d, 0x0e, 4, 0x82, 3, 0xe9
        ];
        der.extend_from_slice(&[0xaa; 1001]);
        assert_eq!(
            value
                .encode_to_vec(&EncodingOptions::new(EncodingType::Der))
                .unwrap(),
            der
        );
        assert_eq!(
            decoded
                .encode_to_vec(&EncodingOptions::new(EncodingType::Der))
                .unwrap(),
            der
        );
    }

    /// subjectKeyIdentifier，非 critical：critical 省略，extnValue 是 OCTET STRING 包 OCTET STRING。
    fn ski() -> Vec<u8> {
        let mut v = alloc::vec![
            0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14
        ];
        v.extend_from_slice(&[0xAB; 20]);
        v
    }

    fn encode(ext: &Extension) -> Vec<u8> {
        let mut out = alloc::vec![0_u8; ext.encoded_len(&EncodingOptions::new(EncodingType::Der))];
        ext.encode(&EncodingOptions::new(EncodingType::Der), &mut out)
            .unwrap();
        out
    }

    #[test]
    fn an_omitted_critical_decodes_as_false_and_stays_omitted() {
        let input = ski();
        let (used, ext) = Extension::try_decode(&input, OPTIONS).unwrap();

        assert_eq!(used, input.len());
        assert_eq!(ext.extn_id().to_string(), "2.5.29.14");
        assert!(!ext.critical());
        assert_eq!(
            ext.extn_value_as::<Asn1OctetString>(OPTIONS)
                .unwrap()
                .as_bytes(),
            &[0xAB; 20]
        );
        assert_eq!(encode(&ext), input);
    }

    #[test]
    fn an_explicit_false_is_accepted_under_ber_and_dropped_on_re_encoding() {
        // 30 12 06 03 55 1D 0E 01 01 00 04 ... —— 多了 01 01 00
        let mut input = ski();
        input.splice(7..7, [0x01, 0x01, 0x00]);
        input[1] += 3;

        let (used, ext) = Extension::try_decode(&input, OPTIONS).unwrap();
        assert_eq!(used, input.len());
        assert!(!ext.critical());

        assert_eq!(encode(&ext), ski(), "DER 下等於預設值就不寫");
    }

    #[test]
    fn a_built_critical_extension_writes_the_boolean() {
        let inner = [0x30, 0x03, 0x01, 0x01, 0xFF]; // SEQUENCE { BOOLEAN TRUE }
        let ext = Extension::new("2.5.29.19".parse().unwrap(), true, &inner);

        assert_eq!(
            encode(&ext),
            [
                0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03,
                0x01, 0x01, 0xFF
            ]
        );
    }

    #[test]
    fn a_missing_extn_value_is_truncated() {
        // 只有 extnID 和 critical
        let input = [0x30, 0x08, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF];
        assert_eq!(
            Extension::try_decode(&input, OPTIONS).err(),
            Some(Asn1Error::Truncated)
        );
    }

    #[test]
    fn inner_der_with_trailing_bytes_is_rejected_when_unwrapped() {
        // extnValue 裡除了 OCTET STRING 還多一個 NULL
        let ext = Extension::new(
            "2.5.29.14".parse().unwrap(),
            false,
            &[0x04, 0x01, 0xAA, 0x05, 0x00],
        );
        assert_eq!(
            ext.extn_value_as::<Asn1OctetString>(OPTIONS).err(),
            Some(Asn1Error::TrailingData)
        );
    }
}
