# tc_asn1

## 1. Overview

`tc_asn1` provides ASN.1 universal values, BER decoding, and BER, CER, and DER
encoding. It also provides tools for reading fields according to an application's
schema and for inspecting data whose schema is unknown.

The crate uses `#![no_std]` and requires `alloc`. It has no external dependencies
or optional Cargo features. The provided value types own their contents;
`Asn1Ref` provides a borrowed view of an encoded element.

### Elements and schemas

An encoded element consists of an identifier (tag), a length, and contents: a TLV.
Constructed contents contain child TLVs. Indefinite-length constructed elements
end with an end-of-contents marker, `00 00`.

The schema determines which type a tag represents. For example, an INTEGER
normally uses tag `02`, but `[0] IMPLICIT INTEGER` uses `80` with the same INTEGER
contents. Concrete value decoders validate the selected type's contents and
primitive/constructed form; they do not require its usual universal identifier.
Use `Fields` or inspect `Asn1Ref::tag()` to check the identifier expected by the
schema. `Asn1Object` instead uses identifiers to select variants when inspecting
data without a schema.

```rust
use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodingOptions, Encode,
    EncodingOptions, EncodingType, tag,
};

fn main() -> Result<(), Asn1Error> {
    let value = Asn1Integer::from(42_u8);
    let wire = value.encode_to_vec(&EncodingOptions::new(EncodingType::Der))?;
    assert_eq!(wire, [0x02, 0x01, 0x2a]);

    let options = DecodingOptions::default();
    let element = Asn1Ref::parse(&wire, options)?;
    if element.tag() != tag::INTEGER {
        return Err(Asn1Error::UnexpectedTag);
    }
    let (used, decoded) = Asn1Integer::try_decode(&wire, options)?;
    assert_eq!(used, wire.len());
    assert_eq!(decoded, value);
    Ok(())
}
```

### Encoding options

`EncodingType` selects BER, CER, or DER. `EncodingOptions` contains that selection
in a private field and leaves room for additional settings. Construct it with
`EncodingOptions::new(encoding_type)` and read the selection with `encoding_type()`.
`EncodingType` is `Copy`; `EncodingOptions` is not. Length calculation and encoding
borrow the same options through `&EncodingOptions`.

This replaces the former options enum. To migrate, construct an `EncodingType`
inside `EncodingOptions::new`, borrow the options at call sites, and change custom
implementations of `EncodeContent`, `EncodeTagged`, `Encode`, and `SequenceFields`
to accept `&EncodingOptions`. Match on `options.encoding_type()` to inspect the
selected rule. Decoding APIs are unchanged.

```rust
use tc_asn1::{Asn1Integer, Encode, EncodingOptions, EncodingType};

let options = EncodingOptions::new(EncodingType::Der);
let value = Asn1Integer::from(42_u8);
let mut out = vec![0; value.encoded_len(&options)];
value.encode(&options, &mut out)?;
assert_eq!(out, [0x02, 0x01, 0x2A]);
# Ok::<(), tc_asn1::Asn1Error>(())
```

| Encoding type | Behavior for interpreted values |
| --- | --- |
| `Ber(LengthForm::Definite)` | Uses definite lengths and preserves stored collection order. |
| `Ber(LengthForm::Indefinite)` | Uses indefinite lengths for constructed values; primitive values remain definite-length. |
| `Cer` | Uses indefinite lengths for constructed values, segments supported long strings, and applies canonical ordering and value normalization. |
| `Der` | Uses minimal definite lengths, primitive string encodings, and canonical ordering and value normalization. |

BER re-encoding preserves values but may change their original bytes.
`Asn1Any` and `Asn1Object::Unknown` preserve complete raw encodings even when CER
or DER is requested. A schema-free SET also lacks the type information needed
for every canonical ordering rule. Re-encoding is therefore not a complete DER
validator. Signature verification must use the original signed bytes.

### Decoding options and errors

`DecodingOptions` has private fields, a `new(depth, max_content_len, max_children)`
constructor, and the getters `depth()`, `max_content_len()`, and `max_children()`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `depth` | `Depth::DEFAULT`, or 32 levels | Remaining nesting budget along a decoding path. |
| `max_content_len` | 16 MiB | Maximum contents of one element, excluding its outer header and EOC marker. |
| `max_children` | 65,536 | Maximum number of direct children of one constructed element. |

These limits are not a shared budget for total allocations or all nodes in a
tree. Definite-length opaque contents are not traversed during parsing; limits
on their descendants apply when those descendants are decoded or iterated.
Copying options does not spend depth. `Depth::descend()` returns a reduced budget
or `Asn1Error::DepthExceeded` when no levels remain.

```rust
use tc_asn1::{DecodingOptions, Depth};

let options = DecodingOptions::new(Depth::new(8), 4096, 64);
assert_eq!(options.depth().get(), 8);
assert_eq!(options.max_content_len(), 4096);
assert_eq!(options.max_children(), 64);
```

Fallible codec operations return `Asn1Error`. Errors distinguish incomplete
input, unexpected identifiers or forms, invalid contents, exhausted limits,
and insufficient output buffers. The enum is `#[non_exhaustive]`, so downstream
matches need a fallback arm.

Encoding and decoding generally take variable time depending on the input and
allocation sizes. Use these operations for public values; the crate does not
provide constant-time codec alternatives or automatic zeroization of stored values.

## 2. Traits

### Encoding

The encoding traits have these prerequisite relationships:

```text
EncodeContent
    ↑ required by
EncodeTagged
    ↑ required by
Encode
```

Each trait requires an explicit implementation. Implementing `EncodeContent`
does not automatically implement `EncodeTagged` or `Encode`. All three support
trait objects, such as `&dyn Encode`.

| Trait | Required methods | Default methods | Responsibility |
| --- | --- | --- | --- |
| `EncodeContent` | `content_len`, `encode_content` | `encode_content_to_vec` | Encodes contents without the outer tag, length, or EOC marker. |
| `EncodeTagged: EncodeContent` | None | `encoded_len_tagged`, `encode_tagged` | Frames contents with a caller-supplied tag. |
| `Encode: EncodeTagged` | `encoded_len`, `encode` | `encode_to_vec` | Encodes a complete element, selecting its usual tag internally or preserving its raw encoding. |

Length methods report bytes, and their results must match the number of bytes
written with the same options. Buffer-based methods return the number written;
the `*_to_vec` methods allocate the output. Constructed contents include child
TLVs, and CER string contents may include segment TLVs.

`EncodeTagged` supplies default framing methods that types can override for
special encodings, including CER string segmentation. The caller supplies valid,
nonempty identifier octets with an appropriate class and form; the default
implementation does not validate the identifier.

### Decoding

The decoding traits are independent: none inherits from another, and there is
no blanket implementation deriving `Decode` from `DecodeContent`.

| Trait | Method | Input | Result |
| --- | --- | --- | --- |
| `DecodeContent<'a>` | `try_decode_content` | Contents without the outer header. | `Result<Self, Asn1Error>` |
| `DecodeConstructed<'a>` | `try_decode_constructed` | Component TLVs inside a constructed string. | `Result<Self, Asn1Error>` |
| `Decode<'a>` | `try_decode` | A buffer starting with a complete TLV. | `Result<(usize, Self), Asn1Error>` |

Each method accepts `DecodingOptions`. The lifetime `'a` allows implementations
to borrow from the input; it does not require them to borrow. All three traits
require `Sized`, so they are used with concrete types or generics rather than
trait objects.

`DecodeContent` has no outer identifier to inspect. Its caller chooses the type
and content form. `DecodeConstructed` is only implemented for types supporting
segmented string encodings, such as OCTET STRING, BIT STRING, and supported
character strings. It validates component identifiers and joins their contents;
it is not a general decoder for every constructed type. SEQUENCE and SET contents
are handled by their `DecodeContent` implementations.

`Decode::try_decode` consumes one element and returns its size. Following bytes
belong to the caller. If the input must contain exactly one element, compare the
returned size with the buffer length. This check is separate from validating
contents: a BOOLEAN with two content bytes or a NULL with nonempty contents is
invalid even when trailing bytes outside a valid TLV would be allowed.

`Asn1Ref::decode_as::<T>()` calls `T::try_decode` and requires consumption of the
entire referenced element. It does not select or validate the schema's identifier
for `T`. `decode_constructed_as::<T>()` selects the constructed-content or
primitive-content entry point from the constructed bit. `DecodeConstructed`
requires `DecodeContent`, so both entries are available.

Every fixed universal type exposes its identifier as `TAG`, for example
`Asn1Integer::TAG`. Types supporting constructed encodings also expose
`CONSTRUCTED_TAG`, so a schema can match
`Asn1OctetString::TAG | Asn1OctetString::CONSTRUCTED_TAG` without numeric tag
patterns. For types that are always constructed, such as `Asn1SequenceOf<T>`,
the two constants are equal. Dynamic types such as `Asn1Any` and `Asn1Object`
have no single fixed tag. The existing `tag` module remains available.

### Schema fields and custom tags

`EncodeTagged` supports IMPLICIT tagging, which replaces the outer identifier.
`Implicit` is a borrowed encoding wrapper for this operation. `Explicit` instead
wraps the original complete TLV in an additional constructed element.

`Fields` reads the contents of a constructed value. Its `required`, `optional`,
and `default` methods receive the exact identifier chosen by the schema,
including the constructed bit. `implicit` passes contents to `DecodeContent`;
`implicit_constructed` receives the replacement primitive identifier and accepts
its constructed form. `explicit` checks its outer wrapper and reads one inner
element. Use `peek()` and `next()` when a CHOICE or ANY needs custom dispatch.
Complete successful field reads with `finish()` to reject remaining fields.

```rust
use tc_asn1::{
    Asn1Error, Asn1Integer, DecodingOptions, EncodeTagged, EncodingOptions, EncodingType, Fields,
};

fn main() -> Result<(), Asn1Error> {
    let value = Asn1Integer::from(42_u8);
    let tag = &[0x80]; // [0] IMPLICIT INTEGER, as specified by the schema.
    let mut wire = [0; 3];
    let written = value.encode_tagged(tag, &EncodingOptions::new(EncodingType::Der), &mut wire)?;
    assert_eq!(wire, [0x80, 1, 42]);

    // These bytes are a field list containing one element, without a parent header.
    let mut fields = Fields::new(&wire[..written], DecodingOptions::default())?;
    let decoded: Asn1Integer = fields.implicit(tag)?;
    fields.finish()?;
    assert_eq!(decoded, value);
    Ok(())
}
```

For named SEQUENCE encoders, `SequenceFields::fields` sends borrowed fields to a
callback in schema order. Omit OPTIONAL or DEFAULT fields there as appropriate.
`impl_sequence_encode!(Type)` generates explicit implementations of all three
encoding traits using the SEQUENCE identifier. Its two-argument form accepts a
custom identifier. It does not generate decoding implementations. Field
enumeration can occur more than once during length calculation and encoding and
must remain consistent for the same value and options.

## 3. Basic Types

The following tables list the supplied universal value types. Identifiers are
hexadecimal octets for their usual forms, not restrictions on IMPLICIT tagging.
The `tag` module exposes the corresponding constants and supported constructed
string identifiers.

### Scalars and identifiers

| Rust type | ASN.1 type | Identifier | Representation or constraint |
| --- | --- | --- | --- |
| `Asn1Boolean` | BOOLEAN | `01` | Boolean value; BER accepts any nonzero content octet as true. |
| `Asn1Integer` | INTEGER | `02` | Signed integer contents, with conversions to and from Rust integers; no big-integer dependency. |
| `Asn1BitString` | BIT STRING | `03` | Bytes plus a bit length and unused-bit count. |
| `Asn1OctetString` | OCTET STRING | `04` | Arbitrary bytes. |
| `Asn1Null` | NULL | `05` | A value with empty contents. |
| `Asn1Oid` | OBJECT IDENTIFIER | `06` | Encoded arcs; the arc API uses `u64` and the `Arcs` iterator. |
| `Asn1Real` | REAL | `09` | Binary or decimal real representation; conversion to `f64` must be exact. |
| `Asn1Enumerated` | ENUMERATED | `0A` | Integer representation; the schema determines allowed enumeration values. |
| `Asn1RelativeOid` | RELATIVE-OID | `0D` | Relative identifier arcs using `u64`. |
| `Asn1OidIri` | OID-IRI | `1F 23` | Absolute Unicode identifier text with syntax validation. |
| `Asn1RelativeOidIri` | RELATIVE-OID-IRI | `1F 24` | Relative Unicode identifier text with syntax validation. |

### Character strings

| Rust type | ASN.1 type | Identifier | Content handling |
| --- | --- | --- | --- |
| `Asn1Utf8String` | UTF8String | `0C` | Validates UTF-8. |
| `Asn1NumericString` | NumericString | `12` | Digits and spaces. |
| `Asn1PrintableString` | PrintableString | `13` | Validates the ASN.1 PrintableString character set. |
| `Asn1Ia5String` | IA5String | `16` | ASCII characters. |
| `Asn1VisibleString` | VisibleString | `1A` | Printable ASCII characters, including space. |
| `Asn1UniversalString` | UniversalString | `1C` | Four-octet character encodings validated as Unicode scalar values. |
| `Asn1BmpString` | BMPString | `1E` | Two-octet BMP characters; surrogate code points are rejected. |
| `Asn1ObjectDescriptor` | ObjectDescriptor | `07` | Preserves bytes without interpreting character sets. |
| `Asn1TeletexString` | TeletexString | `14` | Preserves bytes without interpreting character sets. |
| `Asn1VideotexString` | VideotexString | `15` | Preserves bytes without interpreting character sets. |
| `Asn1GraphicString` | GraphicString | `19` | Preserves bytes without interpreting character sets. |
| `Asn1GeneralString` | GeneralString | `1B` | Preserves bytes without interpreting character sets. |

Supported constructed string forms are flattened when decoded. DER encoding
writes primitive strings; CER encoding segments supported strings when required
by their encoded content length. BIT STRING segmentation also accounts for the
unused-bit-count octet.

### Dates and times

| Rust type | ASN.1 type | Identifier |
| --- | --- | --- |
| `Asn1Time` | TIME | `0E` |
| `Asn1UtcTime` | UTCTime | `17` |
| `Asn1GeneralizedTime` | GeneralizedTime | `18` |
| `Asn1Date` | DATE | `1F 1F` |
| `Asn1TimeOfDay` | TIME-OF-DAY | `1F 20` |
| `Asn1DateTime` | DATE-TIME | `1F 21` |
| `Asn1Duration` | DURATION | `1F 22` |

These types validate their supported textual formats and normalize encodings
where implemented. They are not a timezone database or a date-arithmetic API.
UTCTime and GeneralizedTime validate calendar components and accept seconds
from 0 through 59; they do not model leap seconds.

### Collections and structured values

| Rust type | ASN.1 type | Identifier | Purpose |
| --- | --- | --- | --- |
| `Asn1SequenceOf<T>` | SEQUENCE OF | `30` | An ordered collection of values decoded as `T`. |
| `Asn1SetOf<T>` | SET OF | `31` | A homogeneous collection with canonical encoding order under CER and DER. |
| `Asn1External` | EXTERNAL | `28` | Optional references and an `ExternalEncoding` alternative. |
| `Asn1EmbeddedPdv` | EMBEDDED PDV | `2B` | A `PdvIdentification` and data bytes. |
| `Asn1CharacterString` | CHARACTER STRING | `3D` | A `PdvIdentification` and data bytes. |

Collection decoding requires `T: Decode<'a>`; encoding requires `T: Encode`.
The selected element decoder determines how each child's contents are interpreted.
If member identifiers require additional schema checks, implement those checks
in the element decoder or read the fields explicitly.

```rust
use tc_asn1::{Asn1Error, Asn1Integer, Asn1SequenceOf, Encode, EncodingOptions, EncodingType};

fn main() -> Result<(), Asn1Error> {
    let values: Asn1SequenceOf<Asn1Integer> =
        [1_u8, 2, 3].into_iter().map(Asn1Integer::from).collect();
    let wire = values.encode_to_vec(&EncodingOptions::new(EncodingType::Der))?;
    assert_eq!(wire, [0x30, 9, 2, 1, 1, 2, 1, 2, 2, 1, 3]);
    Ok(())
}
```

### Borrowed, opaque, and dynamic values

| Type | Purpose |
| --- | --- |
| `Asn1Ref<'a>` | Borrows one TLV and exposes its raw bytes, tag, contents, class, and constructed bit. |
| `Children<'a>` | Iterates child TLVs with decoding limits; stops after an error. |
| `Asn1Class` | Identifies the Universal, Application, ContextSpecific, or Private tag class. |
| `Asn1Any` | Owns one complete raw TLV without assigning a content type; preserves the original encoding. |
| `Asn1Object` | Owns a dynamic value tree with known universal variants, Sequence, Set, Tagged, and Unknown values. |
| `Asn1Tagged` | Owns a non-universal identifier and its `TaggedContent`. |
| `TaggedContent` | Holds primitive bytes or constructed child objects. |

Use typed values when the schema is known, `Asn1Any` when uninterpreted bytes must
be preserved, and `Asn1Object` when inspecting an unknown structure. A constructed
tag alone cannot determine whether a field uses IMPLICIT or EXPLICIT tagging;
that distinction comes from the schema.
