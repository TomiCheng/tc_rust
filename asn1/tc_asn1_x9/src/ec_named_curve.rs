//! X9.62 and SEC 2 named-curve object identifiers.
//!
//! ```text
//! NamedCurve ::= OBJECT IDENTIFIER
//! ```
//!
//! This table identifies curves, not their security suitability or arithmetic.
//! SEC 2 secp192r1 and secp256r1 share the X9.62 prime192v1 and prime256v1
//! OIDs. Their alias constants are not repeated in `ALL`; lookup returns
//! the X9.62 name, so every table entry has a distinct OID.

use tc_asn1::{Asn1Oid, NamedOid};

/// Named-curve constants and lookup, without dependencies on curve implementations.
///
/// ```
/// use tc_asn1::{Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::EcNamedCurve;
///
/// let oid = EcNamedCurve::SECP256K1.oid();
/// let der = oid.encode_to_vec(&EncodingOptions::DER)?;
/// let back = Asn1Oid::decode_der(&der, &DecodingOptions::default())?.1;
/// assert_eq!(EcNamedCurve::from_oid(&back), Some(EcNamedCurve::SECP256K1));
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EcNamedCurve;

impl EcNamedCurve {
    /// The `prime192v1` curve identifier.
    pub const PRIME192V1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01],
        "1.2.840.10045.3.1.1",
        "prime192v1",
    );

    /// The `prime192v2` curve identifier.
    pub const PRIME192V2: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x02],
        "1.2.840.10045.3.1.2",
        "prime192v2",
    );

    /// The `prime192v3` curve identifier.
    pub const PRIME192V3: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x03],
        "1.2.840.10045.3.1.3",
        "prime192v3",
    );

    /// The `prime239v1` curve identifier.
    pub const PRIME239V1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x04],
        "1.2.840.10045.3.1.4",
        "prime239v1",
    );

    /// The `prime239v2` curve identifier.
    pub const PRIME239V2: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x05],
        "1.2.840.10045.3.1.5",
        "prime239v2",
    );

    /// The `prime239v3` curve identifier.
    pub const PRIME239V3: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x06],
        "1.2.840.10045.3.1.6",
        "prime239v3",
    );

    /// The `prime256v1` curve identifier.
    pub const PRIME256V1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        "1.2.840.10045.3.1.7",
        "prime256v1",
    );

    /// The `c2pnb163v1` curve identifier.
    pub const C2PNB163V1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x01],
        "1.2.840.10045.3.0.1",
        "c2pnb163v1",
    );

    /// The `c2pnb163v2` curve identifier.
    pub const C2PNB163V2: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x02],
        "1.2.840.10045.3.0.2",
        "c2pnb163v2",
    );

    /// The `c2pnb163v3` curve identifier.
    pub const C2PNB163V3: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x03],
        "1.2.840.10045.3.0.3",
        "c2pnb163v3",
    );

    /// The `c2pnb176w1` curve identifier.
    pub const C2PNB176W1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x04],
        "1.2.840.10045.3.0.4",
        "c2pnb176w1",
    );

    /// The `c2tnb191v1` curve identifier.
    pub const C2TNB191V1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x05],
        "1.2.840.10045.3.0.5",
        "c2tnb191v1",
    );

    /// The `c2tnb191v2` curve identifier.
    pub const C2TNB191V2: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x06],
        "1.2.840.10045.3.0.6",
        "c2tnb191v2",
    );

    /// The `c2tnb191v3` curve identifier.
    pub const C2TNB191V3: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x07],
        "1.2.840.10045.3.0.7",
        "c2tnb191v3",
    );

    /// The `c2onb191v4` curve identifier.
    pub const C2ONB191V4: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x08],
        "1.2.840.10045.3.0.8",
        "c2onb191v4",
    );

    /// The `c2onb191v5` curve identifier.
    pub const C2ONB191V5: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x09],
        "1.2.840.10045.3.0.9",
        "c2onb191v5",
    );

    /// The `c2pnb208w1` curve identifier.
    pub const C2PNB208W1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x0a],
        "1.2.840.10045.3.0.10",
        "c2pnb208w1",
    );

    /// The `c2tnb239v1` curve identifier.
    pub const C2TNB239V1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x0b],
        "1.2.840.10045.3.0.11",
        "c2tnb239v1",
    );

    /// The `c2tnb239v2` curve identifier.
    pub const C2TNB239V2: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x0c],
        "1.2.840.10045.3.0.12",
        "c2tnb239v2",
    );

    /// The `c2tnb239v3` curve identifier.
    pub const C2TNB239V3: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x0d],
        "1.2.840.10045.3.0.13",
        "c2tnb239v3",
    );

    /// The `c2onb239v4` curve identifier.
    pub const C2ONB239V4: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x0e],
        "1.2.840.10045.3.0.14",
        "c2onb239v4",
    );

    /// The `c2onb239v5` curve identifier.
    pub const C2ONB239V5: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x0f],
        "1.2.840.10045.3.0.15",
        "c2onb239v5",
    );

    /// The `c2pnb272w1` curve identifier.
    pub const C2PNB272W1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x10],
        "1.2.840.10045.3.0.16",
        "c2pnb272w1",
    );

    /// The `c2pnb304w1` curve identifier.
    pub const C2PNB304W1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x11],
        "1.2.840.10045.3.0.17",
        "c2pnb304w1",
    );

    /// The `c2tnb359v1` curve identifier.
    pub const C2TNB359V1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x12],
        "1.2.840.10045.3.0.18",
        "c2tnb359v1",
    );

    /// The `c2pnb368w1` curve identifier.
    pub const C2PNB368W1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x13],
        "1.2.840.10045.3.0.19",
        "c2pnb368w1",
    );

    /// The `c2tnb431r1` curve identifier.
    pub const C2TNB431R1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x14],
        "1.2.840.10045.3.0.20",
        "c2tnb431r1",
    );

    /// The `sect163k1` curve identifier.
    pub const SECT163K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x01], "1.3.132.0.1", "sect163k1");

    /// The `sect163r1` curve identifier.
    pub const SECT163R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x02], "1.3.132.0.2", "sect163r1");

    /// The `sect239k1` curve identifier.
    pub const SECT239K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x03], "1.3.132.0.3", "sect239k1");

    /// The `sect113r1` curve identifier.
    pub const SECT113R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x04], "1.3.132.0.4", "sect113r1");

    /// The `sect113r2` curve identifier.
    pub const SECT113R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x05], "1.3.132.0.5", "sect113r2");

    /// The `secp112r1` curve identifier.
    pub const SECP112R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x06], "1.3.132.0.6", "secp112r1");

    /// The `secp112r2` curve identifier.
    pub const SECP112R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x07], "1.3.132.0.7", "secp112r2");

    /// The `secp160r1` curve identifier.
    pub const SECP160R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x08], "1.3.132.0.8", "secp160r1");

    /// The `secp160k1` curve identifier.
    pub const SECP160K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x09], "1.3.132.0.9", "secp160k1");

    /// The `secp256k1` curve identifier.
    pub const SECP256K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x0a], "1.3.132.0.10", "secp256k1");

    /// The `sect163r2` curve identifier.
    pub const SECT163R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x0f], "1.3.132.0.15", "sect163r2");

    /// The `sect283k1` curve identifier.
    pub const SECT283K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x10], "1.3.132.0.16", "sect283k1");

    /// The `sect283r1` curve identifier.
    pub const SECT283R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x11], "1.3.132.0.17", "sect283r1");

    /// The `sect131r1` curve identifier.
    pub const SECT131R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x16], "1.3.132.0.22", "sect131r1");

    /// The `sect131r2` curve identifier.
    pub const SECT131R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x17], "1.3.132.0.23", "sect131r2");

    /// The `sect193r1` curve identifier.
    pub const SECT193R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x18], "1.3.132.0.24", "sect193r1");

    /// The `sect193r2` curve identifier.
    pub const SECT193R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x19], "1.3.132.0.25", "sect193r2");

    /// The `sect233k1` curve identifier.
    pub const SECT233K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1a], "1.3.132.0.26", "sect233k1");

    /// The `sect233r1` curve identifier.
    pub const SECT233R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1b], "1.3.132.0.27", "sect233r1");

    /// The `secp128r1` curve identifier.
    pub const SECP128R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1c], "1.3.132.0.28", "secp128r1");

    /// The `secp128r2` curve identifier.
    pub const SECP128R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1d], "1.3.132.0.29", "secp128r2");

    /// The `secp160r2` curve identifier.
    pub const SECP160R2: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1e], "1.3.132.0.30", "secp160r2");

    /// The `secp192k1` curve identifier.
    pub const SECP192K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x1f], "1.3.132.0.31", "secp192k1");

    /// The `secp224k1` curve identifier.
    pub const SECP224K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x20], "1.3.132.0.32", "secp224k1");

    /// The `secp224r1` curve identifier.
    pub const SECP224R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x21], "1.3.132.0.33", "secp224r1");

    /// The `secp384r1` curve identifier.
    pub const SECP384R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x22], "1.3.132.0.34", "secp384r1");

    /// The `secp521r1` curve identifier.
    pub const SECP521R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x23], "1.3.132.0.35", "secp521r1");

    /// The `sect409k1` curve identifier.
    pub const SECT409K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x24], "1.3.132.0.36", "sect409k1");

    /// The `sect409r1` curve identifier.
    pub const SECT409R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x25], "1.3.132.0.37", "sect409r1");

    /// The `sect571k1` curve identifier.
    pub const SECT571K1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x26], "1.3.132.0.38", "sect571k1");

    /// The `sect571r1` curve identifier.
    pub const SECT571R1: NamedOid =
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x00, 0x27], "1.3.132.0.39", "sect571r1");

    /// SEC 2 alias of prime192v1; omitted from ALL to avoid duplicate OIDs.
    pub const SECP192R1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 1],
        "1.2.840.10045.3.1.1",
        "secp192r1",
    );

    /// SEC 2 alias of prime256v1; omitted from ALL to avoid duplicate OIDs.
    pub const SECP256R1: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7],
        "1.2.840.10045.3.1.7",
        "secp256r1",
    );

    /// All 58 distinct OIDs, using X9.62 names for the two SEC aliases.
    pub const ALL: &'static [NamedOid] = &[
        Self::PRIME192V1,
        Self::PRIME192V2,
        Self::PRIME192V3,
        Self::PRIME239V1,
        Self::PRIME239V2,
        Self::PRIME239V3,
        Self::PRIME256V1,
        Self::C2PNB163V1,
        Self::C2PNB163V2,
        Self::C2PNB163V3,
        Self::C2PNB176W1,
        Self::C2TNB191V1,
        Self::C2TNB191V2,
        Self::C2TNB191V3,
        Self::C2ONB191V4,
        Self::C2ONB191V5,
        Self::C2PNB208W1,
        Self::C2TNB239V1,
        Self::C2TNB239V2,
        Self::C2TNB239V3,
        Self::C2ONB239V4,
        Self::C2ONB239V5,
        Self::C2PNB272W1,
        Self::C2PNB304W1,
        Self::C2TNB359V1,
        Self::C2PNB368W1,
        Self::C2TNB431R1,
        Self::SECT163K1,
        Self::SECT163R1,
        Self::SECT239K1,
        Self::SECT113R1,
        Self::SECT113R2,
        Self::SECP112R1,
        Self::SECP112R2,
        Self::SECP160R1,
        Self::SECP160K1,
        Self::SECP256K1,
        Self::SECT163R2,
        Self::SECT283K1,
        Self::SECT283R1,
        Self::SECT131R1,
        Self::SECT131R2,
        Self::SECT193R1,
        Self::SECT193R2,
        Self::SECT233K1,
        Self::SECT233R1,
        Self::SECP128R1,
        Self::SECP128R2,
        Self::SECP160R2,
        Self::SECP192K1,
        Self::SECP224K1,
        Self::SECP224R1,
        Self::SECP384R1,
        Self::SECP521R1,
        Self::SECT409K1,
        Self::SECT409R1,
        Self::SECT571K1,
        Self::SECT571R1,
    ];

    /// Returns the canonical table entry, or None for an unknown curve.
    /// Variable time: branches only on the encoding structure.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::{Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::EcNamedCurve;

    #[test]
    fn every_named_curve_encodes_its_dotted_oid_and_is_found_again() {
        assert_eq!(EcNamedCurve::ALL.len(), 58);
        for entry in EcNamedCurve::ALL {
            let oid: Asn1Oid = entry.dotted().parse().unwrap();
            assert_eq!(entry.oid(), oid);
            let wire = oid.encode_to_vec(&EncodingOptions::DER).unwrap();
            let back = Asn1Oid::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1;
            assert_eq!(back.to_string(), entry.dotted());
            assert_eq!(EcNamedCurve::from_oid(&back), Some(*entry));
        }
    }

    #[test]
    fn canonical_curve_entries_have_unique_oids_and_unknown_oids_return_none() {
        for (i, a) in EcNamedCurve::ALL.iter().enumerate() {
            for b in &EcNamedCurve::ALL[..i] {
                assert_ne!(a.oid(), b.oid());
            }
        }
        assert_eq!(EcNamedCurve::from_oid(&"1.2.3".parse().unwrap()), None);
    }

    #[test]
    fn sec_aliases_resolve_to_the_x9_names_without_duplicate_table_entries() {
        assert_eq!(
            EcNamedCurve::SECP192R1.oid(),
            EcNamedCurve::PRIME192V1.oid()
        );
        assert_eq!(
            EcNamedCurve::SECP256R1.oid(),
            EcNamedCurve::PRIME256V1.oid()
        );
        assert_eq!(
            EcNamedCurve::from_oid(&EcNamedCurve::SECP256R1.oid()),
            Some(EcNamedCurve::PRIME256V1)
        );
    }
}
