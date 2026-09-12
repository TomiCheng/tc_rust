//! OID-IRI 與 RELATIVE-OID-IRI 的 UTF-8 線路表示。
//!
//! 依 X.660 §7.3–7.5 驗證標籤字集與連字號位置，不查詢登記資料。
//! 相等性比較原始字串；識別同一個登記節點所需的 A-label 正規化由上層負責。
//! §7.5.3 允許實作者容忍未來可能解除保留的字元；這裡接受列出的純量範圍。

use super::tag;
use crate::{Asn1Error, DecodeContent, Depth, Encode, EncodingType};
use alloc::string::String;

fn valid_label(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    if label.bytes().all(|b| b.is_ascii_digit()) {
        return label.len() == 1 || !label.starts_with('0');
    }
    if label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    let mut chars = label.chars();
    if chars.nth(2) == Some('-') && chars.next() == Some('-') {
        return false;
    }
    label.chars().all(|c| {
        let n = c as u32;
        c.is_ascii_alphanumeric()
            || matches!(c, '-' | '.' | '_' | '~')
            || matches!(n, 0xA0..=0xDFFE | 0xF900..=0xFDCF | 0xFDF0..=0xFFEF)
            || ((0x10000..=0xDFFFD).contains(&n) && n & 0xFFFF <= 0xFFFD)
            || (0xE1000..=0xEFFFD).contains(&n)
    })
}

macro_rules! iri {
    ($name:ident, $tag:ident, $absolute:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            text: String,
        }
        impl $name {
            /// 驗證路徑與每個標籤後複製。變動時間：依字元與路徑長度分支。
            pub fn new(text: &str) -> Result<Self, Asn1Error> {
                let labels = if $absolute {
                    text.strip_prefix('/').ok_or(Asn1Error::MalformedValue)?
                } else {
                    text
                };
                if !labels.split('/').all(valid_label) {
                    return Err(Asn1Error::MalformedValue);
                }
                Ok(Self {
                    text: String::from(text),
                })
            }
            /// 借用原始 UTF-8 路徑；不做登記名稱解析或 A-label 轉換。
            pub fn as_str(&self) -> &str {
                &self.text
            }
        }
        impl<'a> DecodeContent<'a> for $name {
            const TAG: &'static [u8] = tag::$tag;
            /// 變動時間：驗證 UTF-8、路徑與標籤。
            fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
                Self::new(core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?)
            }
        }
        impl Encode for $name {
            fn tag(&self) -> &[u8] {
                tag::$tag
            }
            /// 常數時間：讀取 UTF-8 位元組長度。
            fn content_len(&self, _: EncodingType) -> usize {
                self.text.len()
            }
            /// 變動時間：依 UTF-8 位元組長度複製。
            fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
                out[..self.text.len()].copy_from_slice(self.text.as_bytes());
                Ok(self.text.len())
            }
        }
    };
}
iri!(
    Asn1OidIri,
    OID_IRI,
    true,
    r#"絕對 OID 路徑，以 `/` 開始；不等同於一般 URL。

# Examples

```
use tc_asn1::Asn1OidIri;
let oid = Asn1OidIri::new("/ISO/Registration_Authority/19785.CBEFF").unwrap();
assert!(oid.as_str().starts_with("/ISO/"));
assert!(Asn1OidIri::new("/ISO/01").is_err());
```"#
);
iri!(
    Asn1RelativeOidIri,
    RELATIVE_OID_IRI,
    false,
    r#"相對 OID 路徑，不帶開頭的 `/`。

# Examples

```
use tc_asn1::Asn1RelativeOidIri;
let oid = Asn1RelativeOidIri::new("台北/0/TLV-encoded").unwrap();
assert_eq!(oid.as_str(), "台北/0/TLV-encoded");
assert!(Asn1RelativeOidIri::new("/台北").is_err());
```"#
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decode;
    #[test]
    fn unicode_and_unbounded_integer_labels_round_trip_with_high_tags() {
        for text in [
            "/ISO/0",
            "/台北/123456789012345678901234567890",
            "/a\u{a0}b",
        ] {
            let value = Asn1OidIri::new(text).unwrap();
            let mut out = alloc::vec![0; value.encoded_len(EncodingType::Der)];
            value.encode(EncodingType::Der, &mut out).unwrap();
            assert_eq!(&out[..2], &[0x1F, 0x23]);
            assert_eq!(
                Asn1OidIri::try_decode(&out, Depth::DEFAULT).unwrap().1,
                value
            );
        }
        let value = Asn1RelativeOidIri::new("台北/1").unwrap();
        let mut out = alloc::vec![0; value.encoded_len(EncodingType::Ber)];
        value.encode(EncodingType::Ber, &mut out).unwrap();
        assert_eq!(&out[..2], &[0x1F, 0x24]);
        assert_eq!(
            Asn1RelativeOidIri::try_decode(&out, Depth::DEFAULT)
                .unwrap()
                .1,
            value
        );
        assert_eq!(
            Asn1OidIri::try_decode(&out, Depth::DEFAULT),
            Err(Asn1Error::UnexpectedTag)
        );
    }
    #[test]
    fn invalid_iri_syntax_and_reserved_characters_are_rejected() {
        for text in [
            "",
            "/",
            "/a/",
            "/a//b",
            "/01",
            "/-a",
            "/a-",
            "/ab--c",
            "/a b",
            "/a%20",
            "/a?b",
            "/a#b",
            "/\u{e000}",
            "/\u{ffff}",
            "/\u{1fffe}",
            "/\u{e0001}",
        ] {
            assert!(Asn1OidIri::new(text).is_err(), "{text:?}");
        }
        assert!(Asn1RelativeOidIri::new("").is_err());
        assert!(Asn1OidIri::try_decode_content(&[0xFF], Depth::DEFAULT).is_err());
    }
}
