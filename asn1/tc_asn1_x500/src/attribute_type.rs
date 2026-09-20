//! Attribute types that occur in names, with their text names.
//!
//! Most OIDs are X.520's; the rest come from RFC 4519 (`DC`, `UID`), PKCS#9
//! (`emailAddress` and friends), RFC 3739 (personal data), ISIS-MTT and the
//! CA/Browser Forum EV Guidelines, because they appear in real names. The
//! short names are the RFC 4514 §3 ones where it defines them and each
//! type's registered descriptor otherwise (RFC 4519, X.520, RFC 3739, PKCS#9,
//! the EV Guidelines). Lookup by name ignores case. Bouncy Castle prints
//! some of these differently (`SERIALNUMBER`, `E`, `DN`, `T`); `SN` here is
//! surname as in RFC 4519, not serialNumber.

use core::fmt;

use tc_asn1::Asn1Oid;

/// A known attribute type: its OID and the name it is written with.
///
/// # Examples
///
/// ```
/// use tc_asn1_x500::AttributeType;
///
/// let cn = AttributeType::COMMON_NAME;
/// assert_eq!(cn.short_name(), "CN");
/// assert_eq!(cn.oid().to_string(), "2.5.4.3");
///
/// // Both directions; the name lookup ignores case.
/// assert_eq!(AttributeType::from_oid(&"2.5.4.10".parse()?), Some(AttributeType::ORGANIZATION_NAME));
/// assert_eq!(AttributeType::from_short_name("ou"), Some(AttributeType::ORGANIZATIONAL_UNIT_NAME));
/// assert_eq!(AttributeType::from_short_name("nope"), None);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AttributeType {
    der: &'static [u8],
    dotted: &'static str,
    short_name: &'static str,
}

impl AttributeType {
    const fn new(der: &'static [u8], dotted: &'static str, short_name: &'static str) -> Self {
        Self {
            der,
            dotted,
            short_name,
        }
    }

    pub const COMMON_NAME: Self = Self::new(&[0x55, 0x04, 0x03], "2.5.4.3", "CN");
    pub const SURNAME: Self = Self::new(&[0x55, 0x04, 0x04], "2.5.4.4", "SN");
    pub const SERIAL_NUMBER: Self = Self::new(&[0x55, 0x04, 0x05], "2.5.4.5", "serialNumber");
    pub const COUNTRY_NAME: Self = Self::new(&[0x55, 0x04, 0x06], "2.5.4.6", "C");
    pub const LOCALITY_NAME: Self = Self::new(&[0x55, 0x04, 0x07], "2.5.4.7", "L");
    pub const STATE_OR_PROVINCE_NAME: Self = Self::new(&[0x55, 0x04, 0x08], "2.5.4.8", "ST");
    pub const STREET_ADDRESS: Self = Self::new(&[0x55, 0x04, 0x09], "2.5.4.9", "STREET");
    pub const ORGANIZATION_NAME: Self = Self::new(&[0x55, 0x04, 0x0a], "2.5.4.10", "O");
    pub const ORGANIZATIONAL_UNIT_NAME: Self = Self::new(&[0x55, 0x04, 0x0b], "2.5.4.11", "OU");
    pub const TITLE: Self = Self::new(&[0x55, 0x04, 0x0c], "2.5.4.12", "title");
    pub const DESCRIPTION: Self = Self::new(&[0x55, 0x04, 0x0d], "2.5.4.13", "description");
    pub const BUSINESS_CATEGORY: Self =
        Self::new(&[0x55, 0x04, 0x0f], "2.5.4.15", "businessCategory");
    /// A SEQUENCE OF DirectoryString, not a single string.
    pub const POSTAL_ADDRESS: Self = Self::new(&[0x55, 0x04, 0x10], "2.5.4.16", "postalAddress");
    pub const POSTAL_CODE: Self = Self::new(&[0x55, 0x04, 0x11], "2.5.4.17", "postalCode");
    pub const TELEPHONE_NUMBER: Self =
        Self::new(&[0x55, 0x04, 0x14], "2.5.4.20", "telephoneNumber");
    pub const NAME: Self = Self::new(&[0x55, 0x04, 0x29], "2.5.4.41", "name");
    pub const GIVEN_NAME: Self = Self::new(&[0x55, 0x04, 0x2a], "2.5.4.42", "givenName");
    pub const INITIALS: Self = Self::new(&[0x55, 0x04, 0x2b], "2.5.4.43", "initials");
    pub const GENERATION_QUALIFIER: Self =
        Self::new(&[0x55, 0x04, 0x2c], "2.5.4.44", "generationQualifier");
    /// A BIT STRING.
    pub const X500_UNIQUE_IDENTIFIER: Self =
        Self::new(&[0x55, 0x04, 0x2d], "2.5.4.45", "x500UniqueIdentifier");
    pub const DN_QUALIFIER: Self = Self::new(&[0x55, 0x04, 0x2e], "2.5.4.46", "dnQualifier");
    pub const DMD_NAME: Self = Self::new(&[0x55, 0x04, 0x36], "2.5.4.54", "dmdName");
    pub const PSEUDONYM: Self = Self::new(&[0x55, 0x04, 0x41], "2.5.4.65", "pseudonym");
    pub const ROLE: Self = Self::new(&[0x55, 0x04, 0x48], "2.5.4.72", "role");
    pub const ORGANIZATION_IDENTIFIER: Self =
        Self::new(&[0x55, 0x04, 0x61], "2.5.4.97", "organizationIdentifier");
    /// RFC 3739 personal data; a GeneralizedTime.
    pub const DATE_OF_BIRTH: Self = Self::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x01],
        "1.3.6.1.5.5.7.9.1",
        "dateOfBirth",
    );
    /// RFC 3739 personal data.
    pub const PLACE_OF_BIRTH: Self = Self::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x02],
        "1.3.6.1.5.5.7.9.2",
        "placeOfBirth",
    );
    /// RFC 3739 personal data; a one-character PrintableString.
    pub const GENDER: Self = Self::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x03],
        "1.3.6.1.5.5.7.9.3",
        "gender",
    );
    /// RFC 3739 personal data.
    pub const COUNTRY_OF_CITIZENSHIP: Self = Self::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x04],
        "1.3.6.1.5.5.7.9.4",
        "countryOfCitizenship",
    );
    /// RFC 3739 personal data.
    pub const COUNTRY_OF_RESIDENCE: Self = Self::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x05],
        "1.3.6.1.5.5.7.9.5",
        "countryOfResidence",
    );
    /// ISIS-MTT.
    pub const NAME_AT_BIRTH: Self = Self::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x0e],
        "1.3.36.8.3.14",
        "nameAtBirth",
    );
    /// RFC 4519; an IA5String.
    pub const DOMAIN_COMPONENT: Self = Self::new(
        &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19],
        "0.9.2342.19200300.100.1.25",
        "DC",
    );
    /// RFC 4519.
    pub const USER_ID: Self = Self::new(
        &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01],
        "0.9.2342.19200300.100.1.1",
        "UID",
    );
    /// PKCS#9; an IA5String.
    pub const EMAIL_ADDRESS: Self = Self::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01],
        "1.2.840.113549.1.9.1",
        "emailAddress",
    );
    /// PKCS#9.
    pub const UNSTRUCTURED_NAME: Self = Self::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x02],
        "1.2.840.113549.1.9.2",
        "unstructuredName",
    );
    /// PKCS#9.
    pub const UNSTRUCTURED_ADDRESS: Self = Self::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x08],
        "1.2.840.113549.1.9.8",
        "unstructuredAddress",
    );
    /// CA/Browser Forum EV Guidelines.
    pub const JURISDICTION_LOCALITY_NAME: Self = Self::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x01,
        ],
        "1.3.6.1.4.1.311.60.2.1.1",
        "jurisdictionLocalityName",
    );
    /// CA/Browser Forum EV Guidelines.
    pub const JURISDICTION_STATE_OR_PROVINCE_NAME: Self = Self::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x02,
        ],
        "1.3.6.1.4.1.311.60.2.1.2",
        "jurisdictionStateOrProvinceName",
    );
    /// CA/Browser Forum EV Guidelines.
    pub const JURISDICTION_COUNTRY_NAME: Self = Self::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x03,
        ],
        "1.3.6.1.4.1.311.60.2.1.3",
        "jurisdictionCountryName",
    );

    /// Every known type, for lookups.
    pub const ALL: &'static [Self] = &[
        Self::COMMON_NAME,
        Self::SURNAME,
        Self::SERIAL_NUMBER,
        Self::COUNTRY_NAME,
        Self::LOCALITY_NAME,
        Self::STATE_OR_PROVINCE_NAME,
        Self::STREET_ADDRESS,
        Self::ORGANIZATION_NAME,
        Self::ORGANIZATIONAL_UNIT_NAME,
        Self::TITLE,
        Self::DESCRIPTION,
        Self::BUSINESS_CATEGORY,
        Self::POSTAL_ADDRESS,
        Self::POSTAL_CODE,
        Self::TELEPHONE_NUMBER,
        Self::NAME,
        Self::GIVEN_NAME,
        Self::INITIALS,
        Self::GENERATION_QUALIFIER,
        Self::X500_UNIQUE_IDENTIFIER,
        Self::DN_QUALIFIER,
        Self::DMD_NAME,
        Self::PSEUDONYM,
        Self::ROLE,
        Self::ORGANIZATION_IDENTIFIER,
        Self::DATE_OF_BIRTH,
        Self::PLACE_OF_BIRTH,
        Self::GENDER,
        Self::COUNTRY_OF_CITIZENSHIP,
        Self::COUNTRY_OF_RESIDENCE,
        Self::NAME_AT_BIRTH,
        Self::DOMAIN_COMPONENT,
        Self::USER_ID,
        Self::EMAIL_ADDRESS,
        Self::UNSTRUCTURED_NAME,
        Self::UNSTRUCTURED_ADDRESS,
        Self::JURISDICTION_LOCALITY_NAME,
        Self::JURISDICTION_STATE_OR_PROVINCE_NAME,
        Self::JURISDICTION_COUNTRY_NAME,
    ];

    pub fn oid(&self) -> Asn1Oid {
        Asn1Oid::from_der_bytes(self.der).expect("the table holds valid encodings")
    }

    /// The OID in dotted form.
    pub fn dotted(&self) -> &'static str {
        self.dotted
    }

    pub fn short_name(&self) -> &'static str {
        self.short_name
    }

    /// The known type with this OID, if any. Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|attribute_type| attribute_type.der == oid.as_bytes())
    }

    /// The known type with this short name, compared ignoring ASCII case.
    pub fn from_short_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|attribute_type| attribute_type.short_name.eq_ignore_ascii_case(name))
    }
}

/// The short name.
impl fmt::Display for AttributeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.short_name)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::AttributeType;

    #[test]
    fn every_entry_encodes_its_dotted_form() {
        for attribute_type in AttributeType::ALL {
            let parsed: tc_asn1::Asn1Oid = attribute_type.dotted().parse().unwrap();
            assert_eq!(parsed, attribute_type.oid(), "{}", attribute_type.dotted());
            assert_eq!(attribute_type.oid().to_string(), attribute_type.dotted());
        }
    }

    #[test]
    fn lookups_round_trip_and_ignore_case_in_names() {
        for attribute_type in AttributeType::ALL {
            assert_eq!(
                AttributeType::from_oid(&attribute_type.oid()),
                Some(*attribute_type)
            );
            assert_eq!(
                AttributeType::from_short_name(&attribute_type.short_name().to_uppercase()),
                Some(*attribute_type)
            );
        }
        assert_eq!(
            AttributeType::from_short_name("cn"),
            Some(AttributeType::COMMON_NAME)
        );
        assert_eq!(AttributeType::from_short_name("CN "), None);
        assert_eq!(AttributeType::from_oid(&"1.2.3.4".parse().unwrap()), None);
    }

    #[test]
    fn short_names_are_unique() {
        for (i, a) in AttributeType::ALL.iter().enumerate() {
            for b in &AttributeType::ALL[i + 1..] {
                assert!(!a.short_name().eq_ignore_ascii_case(b.short_name()));
                assert_ne!(a.oid(), b.oid());
            }
        }
    }
}
