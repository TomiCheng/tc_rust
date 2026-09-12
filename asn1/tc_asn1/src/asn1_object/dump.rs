//! 純 core::fmt 的樹狀輸出；十六進位不截斷，每個節點以換行結尾。
//! 未知 universal 號碼超過 u64 時，以 tag= 加完整識別位元組取代十進位號碼。

use super::{Asn1Object, TaggedContent};
use crate::universal::tag_key;
use crate::{Asn1Class, Asn1Integer, ExternalEncoding, PdvIdentification};
use core::fmt;

impl fmt::Display for Asn1Object {
    /// 輸出公開資料的完整樹。變動時間：分支只依編碼結構。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        dump(self, 0, f)
    }
}

fn indent(level: usize, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for _ in 0..level {
        f.write_str("  ")?;
    }
    Ok(())
}

fn hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

fn octets(bytes: &[u8], count: usize, unit: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, " ({count} {unit})")?;
    if !bytes.is_empty() {
        f.write_str(" ")?;
        hex(bytes, f)?;
    }
    Ok(())
}

fn bytes_line(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    octets(bytes, bytes.len(), "bytes", f)?;
    f.write_str("\n")
}

fn integer(value: &Asn1Integer, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if let Ok(number) = i128::try_from(value) {
        write!(f, " {number}")
    } else {
        octets(value.as_bytes(), value.as_bytes().len(), "bytes", f)
    }
}

fn identification(value: &PdvIdentification, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("identification ")?;
    match value {
        PdvIdentification::Syntaxes {
            abstract_syntax,
            transfer_syntax,
        } => write!(f, "syntaxes {abstract_syntax} {transfer_syntax}")?,
        PdvIdentification::Syntax(oid) => write!(f, "syntax {oid}")?,
        PdvIdentification::PresentationContextId(id) => {
            f.write_str("presentation-context-id")?;
            integer(id, f)?;
        }
        PdvIdentification::ContextNegotiation {
            presentation_context_id,
            transfer_syntax,
        } => {
            f.write_str("context-negotiation")?;
            integer(presentation_context_id, f)?;
            write!(f, " {transfer_syntax}")?;
        }
        PdvIdentification::TransferSyntax(oid) => write!(f, "transfer-syntax {oid}")?,
        PdvIdentification::Fixed => f.write_str("fixed")?,
    }
    f.write_str("\n")
}

fn pdv(
    id: &PdvIdentification,
    bytes: &[u8],
    label: &str,
    level: usize,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    indent(level + 1, f)?;
    identification(id, f)?;
    indent(level + 1, f)?;
    f.write_str(label)?;
    bytes_line(bytes, f)
}

fn dump(obj: &Asn1Object, level: usize, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    use Asn1Object::*;
    indent(level, f)?;
    match obj {
        Boolean(value) => writeln!(f, "BOOLEAN {}", value.0),
        Integer(value) => {
            f.write_str("INTEGER")?;
            integer(value, f)?;
            f.write_str("\n")
        }
        Enumerated(value) => {
            f.write_str("ENUMERATED")?;
            if let Ok(number) = i64::try_from(value) {
                writeln!(f, " {number}")
            } else {
                bytes_line(value.as_bytes(), f)
            }
        }
        Real(value) => {
            f.write_str("REAL")?;
            if let Ok(number) = f64::try_from(value) {
                writeln!(f, " {number}")
            } else {
                bytes_line(value.as_bytes(), f)
            }
        }
        BitString(value) => {
            f.write_str("BIT STRING")?;
            octets(value.as_bytes(), value.bit_len(), "bits", f)?;
            f.write_str("\n")
        }
        OctetString(value) => {
            f.write_str("OCTET STRING")?;
            bytes_line(value.as_bytes(), f)
        }
        Null => f.write_str("NULL\n"),
        Oid(value) => writeln!(f, "OBJECT IDENTIFIER {value}"),
        RelativeOid(value) => writeln!(f, "RELATIVE-OID {value}"),
        Utf8String(value) => writeln!(f, "UTF8String {:?}", value.as_str()),
        PrintableString(value) => writeln!(f, "PrintableString {:?}", value.as_str()),
        Ia5String(value) => writeln!(f, "IA5String {:?}", value.as_str()),
        NumericString(value) => writeln!(f, "NumericString {:?}", value.as_str()),
        VisibleString(value) => writeln!(f, "VisibleString {:?}", value.as_str()),
        BmpString(value) => writeln!(f, "BMPString {:?}", value.as_str()),
        UniversalString(value) => writeln!(f, "UniversalString {:?}", value.as_str()),
        ObjectDescriptor(value) => {
            f.write_str("ObjectDescriptor")?;
            bytes_line(value.as_bytes(), f)
        }
        TeletexString(value) => {
            f.write_str("TeletexString")?;
            bytes_line(value.as_bytes(), f)
        }
        VideotexString(value) => {
            f.write_str("VideotexString")?;
            bytes_line(value.as_bytes(), f)
        }
        GraphicString(value) => {
            f.write_str("GraphicString")?;
            bytes_line(value.as_bytes(), f)
        }
        GeneralString(value) => {
            f.write_str("GeneralString")?;
            bytes_line(value.as_bytes(), f)
        }
        UtcTime(value) => writeln!(f, "UTCTime {value}"),
        GeneralizedTime(value) => writeln!(f, "GeneralizedTime {value}"),
        Time(value) => writeln!(f, "TIME {}", value.as_str()),
        Date(value) => writeln!(f, "DATE {}", value.as_str()),
        TimeOfDay(value) => writeln!(f, "TIME-OF-DAY {}", value.as_str()),
        DateTime(value) => writeln!(f, "DATE-TIME {}", value.as_str()),
        Duration(value) => writeln!(f, "DURATION {}", value.as_str()),
        OidIri(value) => writeln!(f, "OID-IRI {}", value.as_str()),
        RelativeOidIri(value) => writeln!(f, "RELATIVE-OID-IRI {}", value.as_str()),
        Sequence(children) | Set(children) => {
            f.write_str(if matches!(obj, Sequence(_)) {
                "SEQUENCE\n"
            } else {
                "SET\n"
            })?;
            for child in children {
                dump(child, level + 1, f)?;
            }
            Ok(())
        }
        External(value) => {
            f.write_str("EXTERNAL\n")?;
            if let Some(oid) = value.direct_reference() {
                indent(level + 1, f)?;
                writeln!(f, "direct-reference {oid}")?;
            }
            if let Some(id) = value.indirect_reference() {
                indent(level + 1, f)?;
                f.write_str("indirect-reference")?;
                integer(id, f)?;
                f.write_str("\n")?;
            }
            if let Some(descriptor) = value.data_value_descriptor() {
                indent(level + 1, f)?;
                f.write_str("data-value-descriptor")?;
                bytes_line(descriptor.as_bytes(), f)?;
            }
            indent(level + 1, f)?;
            match value.encoding() {
                ExternalEncoding::SingleAsn1Type(inner) => {
                    f.write_str("encoding [0]\n")?;
                    dump(inner, level + 2, f)
                }
                ExternalEncoding::OctetAligned(bytes) => {
                    f.write_str("encoding [1]")?;
                    bytes_line(bytes.as_bytes(), f)
                }
                ExternalEncoding::Arbitrary(bits) => {
                    f.write_str("encoding [2]")?;
                    octets(bits.as_bytes(), bits.bit_len(), "bits", f)?;
                    f.write_str("\n")
                }
            }
        }
        EmbeddedPdv(value) => {
            f.write_str("EMBEDDED PDV\n")?;
            pdv(
                value.identification(),
                value.as_bytes(),
                "data-value",
                level,
                f,
            )
        }
        CharacterString(value) => {
            f.write_str("CHARACTER STRING\n")?;
            pdv(
                value.identification(),
                value.as_bytes(),
                "string-value",
                level,
                f,
            )
        }
        Tagged(value) => {
            let class = match value.class() {
                Asn1Class::Application => "APPLICATION",
                Asn1Class::ContextSpecific => "CONTEXT",
                Asn1Class::Private => "PRIVATE",
                Asn1Class::Universal => unreachable!("tagged values reject universal tags"),
            };
            write!(f, "[{class} {}]", value.number())?;
            match value.content() {
                TaggedContent::Constructed(children) => {
                    f.write_str("\n")?;
                    for child in children {
                        dump(child, level + 1, f)?;
                    }
                    Ok(())
                }
                TaggedContent::Primitive(bytes) => bytes_line(bytes, f),
            }
        }
        Unknown(value) => {
            let element = value.as_ref();
            match tag_key(element.tag()) {
                Ok((_, number)) => write!(f, "[UNIVERSAL {number}]")?,
                Err(_) => {
                    f.write_str("[UNIVERSAL tag=")?;
                    hex(element.tag(), f)?;
                    f.write_str("]")?;
                }
            }
            if element.is_constructed() {
                f.write_str(" constructed")?;
            }
            bytes_line(element.value(), f)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use alloc::{boxed::Box, string::ToString, vec};

    #[test]
    fn numeric_dumps_use_decimal_when_exact_and_full_hex_otherwise() {
        let huge = [1; 17];
        let tree: Asn1Object = Asn1Integer::from_der_bytes(&huge).unwrap().into();
        assert_eq!(
            tree.to_string(),
            "INTEGER (17 bytes) 0101010101010101010101010101010101\n"
        );
        let tree: Asn1Object = Asn1Enumerated::from(u64::MAX).into();
        assert_eq!(
            tree.to_string(),
            "ENUMERATED (9 bytes) 00ffffffffffffffff\n"
        );
        assert_eq!(
            Asn1Object::from(Asn1Integer::from(-7_i64)).to_string(),
            "INTEGER -7\n"
        );
        assert_eq!(
            Asn1Object::from(Asn1Enumerated::from(-1_i64)).to_string(),
            "ENUMERATED -1\n"
        );
        assert_eq!(
            Asn1Object::from(Asn1Real::from(1.5_f64)).to_string(),
            "REAL 1.5\n"
        );
        let inexact = Asn1Real::from_decimal_parts(false, "1", "-1").unwrap();
        assert_eq!(inexact.as_bytes(), b"\x031.E-1");
        assert_eq!(
            Asn1Object::from(inexact).to_string(),
            "REAL (6 bytes) 03312e452d31\n"
        );
        assert_eq!(
            Asn1Object::from(Asn1BitString::from_bits(&[0xa0], 3)).to_string(),
            "BIT STRING (3 bits) a0\n"
        );
        assert_eq!(
            Asn1Object::from(Asn1BitString::from_bytes(&[])).to_string(),
            "BIT STRING (0 bits)\n"
        );
    }

    #[test]
    fn text_dumps_escape_strings_but_leave_times_and_iris_unquoted() {
        let cases: [(Asn1Object, &str); 16] = [
            (
                Asn1Utf8String::new("台\n\"").into(),
                "UTF8String \"台\\n\\\"\"\n",
            ),
            (
                Asn1PrintableString::new("a").unwrap().into(),
                "PrintableString \"a\"\n",
            ),
            (Asn1Ia5String::new("a").unwrap().into(), "IA5String \"a\"\n"),
            (
                Asn1NumericString::new("1 ").unwrap().into(),
                "NumericString \"1 \"\n",
            ),
            (
                Asn1VisibleString::new("~").unwrap().into(),
                "VisibleString \"~\"\n",
            ),
            (
                Asn1BmpString::new("台").unwrap().into(),
                "BMPString \"台\"\n",
            ),
            (
                Asn1UniversalString::new("😀").into(),
                "UniversalString \"😀\"\n",
            ),
            (
                Asn1UtcTime::new(2023, 1, 1, 0, 0, 0).unwrap().into(),
                "UTCTime 2023-01-01T00:00:00Z\n",
            ),
            (
                Asn1GeneralizedTime::new(2023, 1, 1, 0, 0, 0)
                    .unwrap()
                    .into(),
                "GeneralizedTime 2023-01-01T00:00:00Z\n",
            ),
            (
                Asn1Time::new("2024-01-01T12:30").unwrap().into(),
                "TIME 2024-01-01T12:30\n",
            ),
            (
                Asn1Date::new("2024-01-01").unwrap().into(),
                "DATE 2024-01-01\n",
            ),
            (
                Asn1TimeOfDay::new("12:30:00").unwrap().into(),
                "TIME-OF-DAY 12:30:00\n",
            ),
            (
                Asn1DateTime::new("2024-01-01T12:30:00").unwrap().into(),
                "DATE-TIME 2024-01-01T12:30:00\n",
            ),
            (Asn1Duration::new("P1D").unwrap().into(), "DURATION P1D\n"),
            (
                Asn1OidIri::new("/ISO/台北").unwrap().into(),
                "OID-IRI /ISO/台北\n",
            ),
            (
                Asn1RelativeOidIri::new("台北/1").unwrap().into(),
                "RELATIVE-OID-IRI 台北/1\n",
            ),
        ];
        for (tree, expected) in cases {
            assert_eq!(tree.to_string(), expected);
        }
    }

    #[test]
    fn opaque_dumps_keep_all_octets_and_do_not_add_trailing_spaces_for_empty_values() {
        let cases: [(Asn1Object, &str); 6] = [
            (
                Asn1ObjectDescriptor::new(&[0, 0xff]).into(),
                "ObjectDescriptor (2 bytes) 00ff\n",
            ),
            (
                Asn1TeletexString::new(&[0, 0xff]).into(),
                "TeletexString (2 bytes) 00ff\n",
            ),
            (
                Asn1VideotexString::new(&[0, 0xff]).into(),
                "VideotexString (2 bytes) 00ff\n",
            ),
            (
                Asn1GraphicString::new(&[0, 0xff]).into(),
                "GraphicString (2 bytes) 00ff\n",
            ),
            (
                Asn1GeneralString::new(&[]).into(),
                "GeneralString (0 bytes)\n",
            ),
            (Asn1OctetString::new(&[]).into(), "OCTET STRING (0 bytes)\n"),
        ];
        for (tree, expected) in cases {
            assert_eq!(tree.to_string(), expected);
        }
    }

    #[test]
    fn external_dumps_include_present_fields_and_distinguish_all_encoding_choices() {
        let tree: Asn1Object = Asn1External::new(
            Some("1.2.3".parse().unwrap()),
            Some(Asn1Integer::from(7_u8)),
            Some(Asn1ObjectDescriptor::new(b"x")),
            ExternalEncoding::SingleAsn1Type(Box::new(Asn1Object::Null)),
        )
        .into();
        assert_eq!(
            tree.to_string(),
            concat!(
                "EXTERNAL\n  direct-reference 1.2.3\n  indirect-reference 7\n",
                "  data-value-descriptor (1 bytes) 78\n  encoding [0]\n    NULL\n"
            )
        );
        let tree: Asn1Object = Asn1External::new(
            None,
            None,
            None,
            ExternalEncoding::OctetAligned(Asn1OctetString::new(b"AB")),
        )
        .into();
        assert_eq!(
            tree.to_string(),
            "EXTERNAL\n  encoding [1] (2 bytes) 4142\n"
        );
        let tree: Asn1Object = Asn1External::new(
            None,
            None,
            None,
            ExternalEncoding::Arbitrary(Asn1BitString::from_bits(&[0xa0], 3)),
        )
        .into();
        assert_eq!(tree.to_string(), "EXTERNAL\n  encoding [2] (3 bits) a0\n");
    }

    #[test]
    fn pdv_dumps_name_each_identification_choice_and_the_correct_data_field() {
        let cases = [
            (
                PdvIdentification::Syntaxes {
                    abstract_syntax: "1.2".parse().unwrap(),
                    transfer_syntax: "1.3".parse().unwrap(),
                },
                "syntaxes 1.2 1.3",
            ),
            (
                PdvIdentification::Syntax("1.2".parse().unwrap()),
                "syntax 1.2",
            ),
            (
                PdvIdentification::PresentationContextId(Asn1Integer::from(7_u8)),
                "presentation-context-id 7",
            ),
            (
                PdvIdentification::ContextNegotiation {
                    presentation_context_id: Asn1Integer::from(7_u8),
                    transfer_syntax: "1.2".parse().unwrap(),
                },
                "context-negotiation 7 1.2",
            ),
            (
                PdvIdentification::TransferSyntax("1.2".parse().unwrap()),
                "transfer-syntax 1.2",
            ),
            (PdvIdentification::Fixed, "fixed"),
        ];
        for (id, label) in cases {
            let tree: Asn1Object = Asn1EmbeddedPdv::new(id.clone(), vec![0xaa]).into();
            assert_eq!(
                tree.to_string(),
                alloc::format!(
                    "EMBEDDED PDV\n  identification {label}\n  data-value (1 bytes) aa\n"
                )
            );
            let tree: Asn1Object = Asn1CharacterString::new(id, vec![]).into();
            assert_eq!(
                tree.to_string(),
                alloc::format!(
                    "CHARACTER STRING\n  identification {label}\n  string-value (0 bytes)\n"
                )
            );
        }
    }

    #[test]
    fn unknown_unbounded_tag_numbers_are_shown_without_truncation_or_panics() {
        let input = [
            0x1f, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0,
        ];
        let (_, tree) = Asn1Object::try_decode(&input, Depth::DEFAULT).unwrap();
        assert_eq!(
            tree.to_string(),
            "[UNIVERSAL tag=1f82808080808080808000] (0 bytes)\n"
        );
        assert_eq!(
            crate::universal::encode_member(&tree, EncodingType::Der).unwrap(),
            input
        );
        let set = Asn1Object::Set(vec![tree]);
        assert_eq!(
            crate::universal::encode_member(&set, EncodingType::Der),
            Err(Asn1Error::TagOverflow)
        );
    }
}
