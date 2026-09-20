# tc_asn1_x500

Distinguished names for X.509 and friends: the X.501 `Name` with its
`RelativeDistinguishedName` and `AttributeTypeAndValue`, the X.520
`DirectoryString`, and a table of the attribute types that appear in names.
Certificates only borrow these for subject and issuer, so they live apart
from the certificate crate.

The crate is `no_std` + `alloc` and built on `tc_asn1`: every type decodes
from BER/CER/DER, encodes under any of the three rule sets, and keeps what it
decoded (unknown attribute values round-trip as decoded ASN.1 trees). Names
also have their RFC 4514 text form both ways, and the relaxed comparison that
RFC 5280 §7.1 asks for when matching an issuer to a subject.

## Usage

```rust
use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions, EncodingType};
use tc_asn1_x500::{AttributeType, AttributeTypeAndValue, AttributeValue, DirectoryString, Name};

// The RFC 4514 text form is the easy way to build a name ...
let name: Name = "CN=Alice,O=Example,C=TW".parse()?;

// ... and it prints back the same way. The RDNs are stored root first.
assert_eq!(name.to_string(), "CN=Alice,O=Example,C=TW");
assert_eq!(name.rdns().len(), 3);

// DER out, DER (or BER) in.
let der = name.encode_to_vec(&EncodingOptions::new(EncodingType::Der))?;
let (_, decoded) = Name::decode(&der, &DecodingOptions::default())?;
assert_eq!(decoded, name);

// Walk the structure: each RDN holds one or more type=value pairs.
for rdn in decoded.rdns() {
    for attribute in rdn.attributes() {
        let label = match AttributeType::from_oid(attribute.attribute_type()) {
            Some(known) => known.name(),
            None => "?",
        };
        if let AttributeValue::DirectoryString(text) = attribute.value() {
            println!("{label} = {text}");
        }
    }
}

// `==` is the strict DER comparison; `equivalent` ignores the string type,
// case and extra whitespace, as path validation must.
let issuer: Name = "cn=ALICE, o=example, c=TW".parse()?;
assert_ne!(issuer, name);
assert!(issuer.equivalent(&name));
# Ok::<(), tc_asn1::Asn1Error>(())
```

Building a name from parts, when the values come from somewhere else:

```rust
use tc_asn1_x500::{AttributeType, AttributeTypeAndValue, DirectoryString, Name, RelativeDistinguishedName};

let cn = AttributeTypeAndValue::new(AttributeType::COMMON_NAME.oid(), DirectoryString::new("Alice")?);
let name = Name::new(vec![RelativeDistinguishedName::single(cn)]);
assert_eq!(name.to_string(), "CN=Alice");
# Ok::<(), tc_asn1::Asn1Error>(())
```

## Types

| Type | ASN.1 | Notes |
| --- | --- | --- |
| `Name` | `SEQUENCE OF RelativeDistinguishedName` | Root first. May be empty (RFC 5280 allows an empty subject). `Display`/`FromStr` in RFC 4514 form, most specific first. `equivalent` compares RDNs pairwise. |
| `RelativeDistinguishedName` | `SET SIZE (1..MAX) OF AttributeTypeAndValue` | Usually one attribute. DER/CER sort the members; `==` is order-independent. `equivalent` matches members in any order. |
| `AttributeTypeAndValue` | `SEQUENCE { type OID, value ANY }` | `equivalent` needs the same OID and equivalent values. |
| `AttributeValue` | the `ANY` | Classified by identifier when decoding: `DirectoryString`, `Ia5String` (DC, emailAddress) or `Other(Asn1Object)`. The OID is not consulted. |
| `DirectoryString` | `CHOICE` of PrintableString, UTF8String, TeletexString, BMPString, UniversalString | `new` picks PrintableString when the text allows, else UTF8String. Non-empty. TeletexString is kept as octets. `equivalent` compares text lowercased with whitespace collapsed. |
| `AttributeType` | – | The table below: OID, dotted form and short name, with lookup both ways. |

Not here: name constraints matching (prefix of RDNs), which waits for the
x509 extension; full RFC 4518 string preparation (Unicode case folding and
normalization), which `equivalent` approximates.

## Attribute types

Short names are RFC 4514 §3 where it defines one and the registered
descriptor otherwise. Lookup by name ignores case.

| Short name | OID | Source |
| --- | --- | --- |
| `CN` | 2.5.4.3 | X.520 commonName |
| `SN` | 2.5.4.4 | X.520 surname |
| `serialNumber` | 2.5.4.5 | X.520 |
| `C` | 2.5.4.6 | X.520 countryName |
| `L` | 2.5.4.7 | X.520 localityName |
| `ST` | 2.5.4.8 | X.520 stateOrProvinceName |
| `STREET` | 2.5.4.9 | X.520 streetAddress |
| `O` | 2.5.4.10 | X.520 organizationName |
| `OU` | 2.5.4.11 | X.520 organizationalUnitName |
| `title` | 2.5.4.12 | X.520 |
| `description` | 2.5.4.13 | X.520 |
| `businessCategory` | 2.5.4.15 | X.520 |
| `postalAddress` | 2.5.4.16 | X.520; a SEQUENCE OF DirectoryString |
| `postalCode` | 2.5.4.17 | X.520 |
| `telephoneNumber` | 2.5.4.20 | X.520 |
| `name` | 2.5.4.41 | X.520 |
| `givenName` | 2.5.4.42 | X.520 |
| `initials` | 2.5.4.43 | X.520 |
| `generationQualifier` | 2.5.4.44 | X.520 |
| `x500UniqueIdentifier` | 2.5.4.45 | X.520; a BIT STRING |
| `dnQualifier` | 2.5.4.46 | X.520 |
| `dmdName` | 2.5.4.54 | X.520 |
| `pseudonym` | 2.5.4.65 | X.520 |
| `role` | 2.5.4.72 | X.520 |
| `organizationIdentifier` | 2.5.4.97 | X.520 |
| `dateOfBirth` | 1.3.6.1.5.5.7.9.1 | RFC 3739; a GeneralizedTime |
| `placeOfBirth` | 1.3.6.1.5.5.7.9.2 | RFC 3739 |
| `gender` | 1.3.6.1.5.5.7.9.3 | RFC 3739; one PrintableString character |
| `countryOfCitizenship` | 1.3.6.1.5.5.7.9.4 | RFC 3739 |
| `countryOfResidence` | 1.3.6.1.5.5.7.9.5 | RFC 3739 |
| `nameAtBirth` | 1.3.36.8.3.14 | ISIS-MTT |
| `DC` | 0.9.2342.19200300.100.1.25 | RFC 4519 domainComponent; IA5String |
| `UID` | 0.9.2342.19200300.100.1.1 | RFC 4519 userId |
| `emailAddress` | 1.2.840.113549.1.9.1 | PKCS#9; IA5String |
| `unstructuredName` | 1.2.840.113549.1.9.2 | PKCS#9 |
| `unstructuredAddress` | 1.2.840.113549.1.9.8 | PKCS#9 |
| `jurisdictionLocalityName` | 1.3.6.1.4.1.311.60.2.1.1 | CA/Browser Forum EV Guidelines |
| `jurisdictionStateOrProvinceName` | 1.3.6.1.4.1.311.60.2.1.2 | CA/Browser Forum EV Guidelines |
| `jurisdictionCountryName` | 1.3.6.1.4.1.311.60.2.1.3 | CA/Browser Forum EV Guidelines |

Bouncy Castle prints a few of these differently (`SERIALNUMBER`, `SURNAME`,
`E`, `DN`, `T`); `SN` here is surname, as in RFC 4519 and OpenSSL, not
serialNumber.
