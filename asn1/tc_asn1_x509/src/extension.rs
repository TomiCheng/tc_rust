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

use tc_asn1::tag::SEQUENCE as TAG;
use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1OctetString, Asn1Oid, Decode, DecodeContent, Depth, Encode,
    EncodingType, Fields, SequenceFields,
};

/// 一個 X.509 extension。
///
/// # 範例
///
/// ```
/// use tc_asn1::{Asn1Boolean, Asn1SequenceOf, Depth, Encode, EncodingType, Decode};
/// use tc_asn1_x509::Extension;
///
/// // basicConstraints，critical，內容是 SEQUENCE { cA TRUE }
/// let bytes = [
///     0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF,
///     0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF,
/// ];
/// let (used, ext) = Extension::try_decode(&bytes, Depth::DEFAULT)?;
/// assert_eq!(used, bytes.len());
/// assert_eq!(ext.extn_id().to_string(), "2.5.29.19");
/// assert!(ext.critical());
///
/// // 殼裡的東西：知道 2.5.29.19 是 BasicConstraints 才這樣解
/// let inner = ext.extn_value_as::<Asn1SequenceOf<Asn1Boolean>>(Depth::DEFAULT)?;
/// assert_eq!(inner.members(), &[Asn1Boolean(true)]);
///
/// // 重編回原位元組
/// let mut out = vec![0_u8; ext.encoded_len(EncodingType::Der)];
/// ext.encode(EncodingType::Der, &mut out)?;
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
    pub fn extn_value_as<'a, T: Decode<'a>>(&'a self, depth: Depth) -> Result<T, Asn1Error> {
        T::try_decode_exact(self.extn_value.as_bytes(), depth)
    }
}

impl<'a> DecodeContent<'a> for Extension {
    const TAG: &'static [u8] = TAG;

    /// 變動時間：分支只依編碼結構。
    ///
    /// `critical` 是 DEFAULT FALSE：第二個子元素的 tag 是 BOOLEAN 就是它，否則
    /// 視為省略。明寫 `FALSE` 不是 DER，但寬鬆接受；重編時會消失。
    fn try_decode_content(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
        let mut fields = Fields::new(value, depth)?;
        let extn_id = fields.required()?;
        let critical = fields.default(Asn1Boolean(false))?.0;
        let extn_value = fields.required()?;
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
    fn fields(&self, _: EncodingType, sink: &mut dyn FnMut(&dyn Encode)) {
        sink(&self.extn_id);
        if self.critical {
            sink(&Asn1Boolean(true));
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

    const DEPTH: Depth = Depth::DEFAULT;

    /// subjectKeyIdentifier，非 critical：critical 省略，extnValue 是 OCTET STRING 包 OCTET STRING。
    fn ski() -> Vec<u8> {
        let mut v = alloc::vec![
            0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14
        ];
        v.extend_from_slice(&[0xAB; 20]);
        v
    }

    fn encode(ext: &Extension) -> Vec<u8> {
        let mut out = alloc::vec![0_u8; ext.encoded_len(EncodingType::Der)];
        ext.encode(EncodingType::Der, &mut out).unwrap();
        out
    }

    #[test]
    fn an_omitted_critical_decodes_as_false_and_stays_omitted() {
        let input = ski();
        let (used, ext) = Extension::try_decode(&input, DEPTH).unwrap();

        assert_eq!(used, input.len());
        assert_eq!(ext.extn_id().to_string(), "2.5.29.14");
        assert!(!ext.critical());
        assert_eq!(
            ext.extn_value_as::<Asn1OctetString>(DEPTH)
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

        let (used, ext) = Extension::try_decode(&input, DEPTH).unwrap();
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
            Extension::try_decode(&input, DEPTH).err(),
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
            ext.extn_value_as::<Asn1OctetString>(DEPTH).err(),
            Some(Asn1Error::TrailingData)
        );
    }
}
