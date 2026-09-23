# Work order: `tc_asn1_x9` — X9.62 / SEC 1 elliptic curve ASN.1

A new crate in the incubator, sibling to `tc_asn1_x500` and `tc_asn1_x509`,
depending only on `tc_asn1` 0.1.1. It carries the elliptic curve structures
that key and signature encoding need: the domain parameters a key names or
spells out, the private key file format, and the ECDSA signature value.

## Why

`SubjectPublicKeyInfo` in `tc_asn1_x509` holds an `AlgorithmIdentifier` whose
`parameters` for `id-ecPublicKey` are X9.62 `Parameters`, and a future PKCS
crate will wrap `ECPrivateKey` in a PKCS#8 `PrivateKeyInfo`. Neither crate can
define those structures without pulling in the other, so they live here, in a
crate that depends on nothing but `tc_asn1`.

**This crate must not depend on `tc_asn1_x500` or `tc_asn1_x509`**, and they
must not depend on it. The consumer joins the pieces.

## Out of scope

- X9.42 Diffie-Hellman (`DHParameter`, `DomainParameters`, `ValidationParms`)
  and X9.63 key derivation (`OtherInfo`, `KeySpecificInfo`). Separate work
  order, same crate later.
- Curve arithmetic of any kind: no primality test on the field, no check that
  the base point lies on the curve, no cofactor or order verification, no
  signature verification. This crate moves octets between ASN.1 and Rust types
  and enforces only what the encoding itself states.
- PKCS#8 wrapping, SEC 1 `ECDSA-Signature` with recovery, ECIES.
- Brainpool and other non-X9/SEC named curves: their OIDs live in the TeleTrusT
  arc, not this one.
- Zeroization — see **Secrets** below.

## Crate conventions

- Path `asn1/tc_asn1_x9`, package `tc_asn1_x9`. The workspace `asn1/*` glob
  picks it up; nothing else in the root manifest changes.
- `Cargo.toml` exactly like `tc_asn1_x500`'s, with
  `description = "X9.62 and SEC 1 elliptic curve structures on top of tc_asn1."`
  and one dependency, `tc_asn1 = "0.1.1"`.
- `#![no_std]` and `extern crate alloc;` at the top of `lib.rs`; `lib.rs` holds
  only `//!`, `mod` and `pub use` — no code. No `mod.rs`.
- Code, doc comments and test names in English, as in `tc_asn1`,
  `tc_asn1_x500` and `tc_asn1_x509`.
- LF line endings.

Every public type gets:

- a module doc opening with the spec reference and a ` ```text ` block holding
  the ASN.1 it implements;
- a type doc with a doctest that builds, encodes and decodes a value;
- `#[derive(Clone, Debug, Eq, PartialEq, Hash)]` — `Debug` is derived except
  where this order says otherwise;
- `Display` where a useful one-line rendering exists;
- the trait set the sibling crates use: `DecodeInner`, `Decode`, `Tagged`,
  `EncodeContent`, `EncodeTagged`, `Encode`. A CHOICE type has no single tag,
  so it implements `DecodeInner`, `Decode`, `EncodeContent` and `Encode` with a
  private `tag()` method and **no** `Tagged`, as `GeneralName` and
  `DistributionPointName` do in `tc_asn1_x509`.
- **No `DecodeContent`.** No type here appears under an IMPLICIT tag; do not
  add it speculatively.

Decoding shape, as in the sibling crates:

```rust
let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
let mut fields = element.children(context)?;
let a = fields.get()?;
let b = fields.get_opt()?;
fields.end()?;
Ok((element.total_len(), Self::new(a, b)?))
```

Validation lives in `new`; decoding calls `new`, so both paths enforce the same
rules. Errors: a broken rule is `MalformedValue`, a wrong identifier is
`UnexpectedTag`, a missing required field is `Truncated`, an extra field is
`TrailingData`.

Test function names are full sentences stating the property under test, not the
method called.

## Constant time

Every public method's doc states constant or variable time, as the repo
requires. Everything in this crate is variable time and says so:
`"Variable time: branches only on the encoding structure."` For
`EcPrivateKey`, the doc adds that the private key octets are copied without the
code ever branching on their value; only their length, which is public, affects
control flow.

## Secrets

`EcPrivateKey` holds private key material.

- **No `zeroize` dependency, for now.** Erasing the key octets needs a change
  in `tc_asn1` first: `Asn1OctetString` exposes only `as_bytes(&self)`, so
  nothing outside that crate can wipe it, and the orphan rule blocks
  implementing `Zeroize` for it here. Copying the secret into a
  `Zeroizing<Vec<u8>>` on this side would leave the original `Asn1OctetString`
  unwiped and add a second copy, which is worse than not trying. The tc_asn1
  side is tracked as TomiCheng/tc_asn1#3 and is deferred; when it ships, this
  item gets `Zeroize`, `ZeroizeOnDrop` and a hand-written `Drop`.
- Until then the type doc says plainly that the octets are **not** wiped and
  that the caller owns their lifetime. Do not imply otherwise.
- `Debug` is **hand-written**, printing
  `EcPrivateKey { private_key: <redacted, 32 octets>, parameters: .., public_key: .. }`.
  This keeps the key out of logs and panic messages; the doc says it is a
  convenience, not a security boundary.
- `into_private_key(self) -> Asn1OctetString` lets the caller move the octets
  out instead of cloning them.
- No `Display`.

## Items

Build bottom-up, one commit per item, `feat(x9): …`.

### 1. `FieldId` — `field_id.rs`

```text
FieldID ::= SEQUENCE {
    fieldType  OBJECT IDENTIFIER,
    parameters ANY DEFINED BY fieldType }
```

The identifier fixes the parameter type, so bind them in one enum — the shape
`PolicyQualifierInfo` uses in `tc_asn1_x509`, where a mismatched pair cannot be
built:

```rust
#[non_exhaustive]
pub enum FieldId {
    /// id-prime-field 1.2.840.10045.1.1; the parameter is the prime `p`.
    PrimeField(Asn1Integer),
    /// id-characteristic-two-field 1.2.840.10045.1.2.
    CharacteristicTwoField(CharacteristicTwo),
    /// Any other field type, with its parameter preserved as a tree.
    Other(UnknownField),
}
```

`UnknownField { field_type: Asn1Oid, parameters: Asn1Object }` lives in the same
file with `field_type()` and `parameters()` getters, as
`UnknownPolicyQualifier` does.

API:

- `prime_field(p: impl Into<Asn1Integer>) -> Result<Self, Asn1Error>` —
  `MalformedValue` unless `p` is positive and odd. No primality test.
- `characteristic_two_field(CharacteristicTwo) -> Self`
- `other(field_type, parameters) -> Result<Self, Asn1Error>` — the two known
  OIDs are `MalformedValue`; use their variants.
- `field_type(&self) -> Asn1Oid` — derived from the variant.
- `field_size_bytes(&self) -> usize` — `p.bit_len().div_ceil(8)` for a prime
  field, `m.div_ceil(8)` for a characteristic-two field, and for `Other` the
  length of the DER value of `parameters` is meaningless, so this returns
  `None`: make the signature `field_size_bytes(&self) -> Option<usize>`. Item 4
  uses it and rejects a `Curve` whose field size is unknown only when a length
  rule would apply (see there).
- Constants `PRIME_FIELD` and `CHARACTERISTIC_TWO_FIELD` as `NamedOid`, public.

Tests: both known field types round-trip; an even or non-positive `p` is
rejected on construction and on decoding; an unknown OID keeps its parameter
tree byte-for-byte; `other()` refuses the two known OIDs; a missing or extra
field gives `Truncated` / `TrailingData`.

### 2. `CharacteristicTwo`, `Basis`, `Pentanomial` — `characteristic_two.rs`

```text
Characteristic-two ::= SEQUENCE {
    m          INTEGER,                    -- field size 2^m
    basis      OBJECT IDENTIFIER,
    parameters ANY DEFINED BY basis }

gnBasis  1.2.840.10045.1.2.3.1  parameters NULL
tpBasis  1.2.840.10045.1.2.3.2  parameters Trinomial  ::= INTEGER
ppBasis  1.2.840.10045.1.2.3.3  parameters Pentanomial ::= SEQUENCE {
             k1 INTEGER, k2 INTEGER, k3 INTEGER }
```

Three types in one file, as `policy_mappings.rs` holds `PolicyMapping` and
`PolicyMappings`:

```rust
pub struct CharacteristicTwo { m: u32, basis: Basis }

#[non_exhaustive]
pub enum Basis {
    Gaussian,
    Trinomial(u32),
    Pentanomial(Pentanomial),
    Other(UnknownBasis),
}

pub struct Pentanomial { k1: u32, k2: u32, k3: u32 }
```

`m` and the `k`s are exponents bounded by the field size, not arbitrary
integers, so they are `u32` here rather than `Asn1Integer`: a value that does
not fit is `MalformedValue` on decoding. This differs from the rest of the
workspace, where INTEGER fields stay `Asn1Integer`; the justification is that
these are array indices for the implementation that consumes them, and a field
of 2^(2^32) is not a thing.

Rules, all in the constructors:

- `m >= 1`.
- `Basis::Trinomial(k)`: `0 < k < m`.
- `Pentanomial::new(k1, k2, k3)`: `0 < k1 < k2 < k3 < m`.
- Gaussian: the parameter must be NULL on decoding; encode NULL.
- `Other`: any OID other than the three, parameter kept as `Asn1Object`.

Because the `k` rules need `m`, put the check in
`CharacteristicTwo::new(m: u32, basis: Basis) -> Result<Self, Asn1Error>`, and
let `Pentanomial::new(k1, k2, k3) -> Result<Self, Asn1Error>` check only the
ordering among its own three values.

Tests: each of the three bases round-trips with a fixed DER vector; `k == m`,
`k == 0`, unordered pentanomial coefficients and `m == 0` are each rejected on
construction and on decoding; a Gaussian basis with a non-NULL parameter is
`UnexpectedTag`; an `m` past `u32::MAX` is `MalformedValue`.

### 3. `Curve` — `curve.rs`

```text
Curve ::= SEQUENCE {
    a    FieldElement,
    b    FieldElement,
    seed BIT STRING OPTIONAL }

FieldElement ::= OCTET STRING
```

```rust
pub fn new(a: Asn1OctetString, b: Asn1OctetString) -> Self
pub fn with_seed(self, seed: Asn1BitString) -> Self
pub fn a(&self) -> &Asn1OctetString
pub fn b(&self) -> &Asn1OctetString
pub fn seed(&self) -> Option<&Asn1BitString>
```

No length rule here: X9.62 fixes `FieldElement` at the field's octet length, but
`Curve` does not carry the field. The rule belongs to item 4, and the module doc
says so.

Tests: with and without a seed; a wrong element tag is `UnexpectedTag`; an extra
field is `TrailingData`.

### 4. `X9ECParameters` — `x9_ec_parameters.rs`

```text
ECParameters ::= SEQUENCE {
    version  INTEGER { ecpVer1(1) } (ecpVer1),
    fieldID  FieldID,
    curve    Curve,
    base     ECPoint,
    order    INTEGER,
    cofactor INTEGER OPTIONAL }

ECPoint ::= OCTET STRING
```

The version is not stored: it is checked to be 1 on decoding and written as 1
always. `new` does not take it.

```rust
pub fn new(
    field_id: FieldId,
    curve: Curve,
    base: Asn1OctetString,
    order: Asn1Integer,
) -> Result<Self, Asn1Error>
pub fn with_cofactor(self, cofactor: Asn1Integer) -> Result<Self, Asn1Error>
```

Rules, all in `new`/`with_cofactor`, all cheap and none of them curve
arithmetic:

- When `field_id.field_size_bytes()` is `Some(n)`: `curve.a()` and `curve.b()`
  must each be exactly `n` octets. When it is `None` (an unknown field type),
  skip the check rather than guess.
- `base` is not empty, and its first octet decides its length, with `n` as
  above; when `n` is unknown, check only the first octet:
  - `0x00` — the point at infinity; the whole string must be one octet;
  - `0x02` or `0x03` — compressed; `1 + n` octets;
  - `0x04` — uncompressed; `1 + 2n` octets;
  - `0x06` or `0x07` — hybrid; `1 + 2n` octets;
  - anything else is `MalformedValue`.
  Whether the point is on the curve is the consumer's business.
- `order` is positive; `cofactor`, when present, is positive.

Tests: a full round-trip over a hand-checkable synthetic prime field (see
**Vectors**); a version other than 1 is `MalformedValue`; `a` or `b` one octet
short or long is `MalformedValue`; each point form is accepted at its correct
length and rejected at every other; a first octet of `0x05` is
`MalformedValue`; a zero or negative order and a zero cofactor are rejected; an
unknown field type skips the length rules and still round-trips.

### 5. `X962Parameters` — `x962_parameters.rs`

```text
Parameters ::= CHOICE {
    ecParameters ECParameters,
    namedCurve   OBJECT IDENTIFIER,
    implicitlyCA NULL }
```

A CHOICE: private `tag()` returning `tag::SEQUENCE`, `tag::OBJECT_IDENTIFIER`
or `tag::NULL`, no `Tagged`, decode by `match element.tag()`, everything else
`UnexpectedTag`.

```rust
#[non_exhaustive]
pub enum X962Parameters {
    EcParameters(X9ECParameters),
    NamedCurve(Asn1Oid),
    ImplicitlyCa,
}
```

`From<X9ECParameters>` and `From<Asn1Oid>`. `Display`: `implicitlyCA` for the
NULL alternative, the curve's name from item 7 when known and its dotted form
otherwise for a named curve, and `ecParameters` for explicit parameters.

Tests: all three alternatives round-trip; a `0x04` element is `UnexpectedTag`;
a NULL with a non-empty value is rejected; the named-curve Display falls back to
the dotted form for an OID outside the table.

### 6. `EcPrivateKey` — `ec_private_key.rs`

```text
ECPrivateKey ::= SEQUENCE {                  -- RFC 5915, SEC 1 C.4
    version       INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    privateKey    OCTET STRING,
    parameters [0] Parameters OPTIONAL,      -- EXPLICIT
    publicKey  [1] BIT STRING OPTIONAL }     -- EXPLICIT
```

Both optional fields are EXPLICIT: `parameters` because a CHOICE cannot take an
IMPLICIT tag (X.680 §31.2.7), `publicKey` because RFC 5915 writes it that way.
Read them with `fields.get_explicit_opt::<X962Parameters>([0xA0])` and
`fields.get_explicit_opt::<Asn1BitString>([0xA1])`.

```rust
pub fn new(private_key: Asn1OctetString) -> Result<Self, Asn1Error>  // non-empty
pub fn with_parameters(self, parameters: X962Parameters) -> Self
pub fn with_public_key(self, public_key: Asn1BitString) -> Self
pub fn private_key(&self) -> &Asn1OctetString
pub fn into_private_key(self) -> Asn1OctetString
pub fn parameters(&self) -> Option<&X962Parameters>
pub fn public_key(&self) -> Option<&Asn1BitString>
```

Version handled as in item 4. Hand-written `Debug`, no `Display`; see
**Secrets**.

Tests: the RFC 5915 shape in **Vectors** round-trips byte for byte; all four
combinations of the two optional fields round-trip; an empty private key is
rejected on construction and on decoding; a version other than 1 is
`MalformedValue`; the two optional fields in the wrong order give
`TrailingData`; an IMPLICIT `[0]` (`A0` holding the OID contents directly) is
`UnexpectedTag`; `Debug` output does not contain the key octets.

### 7. `EcdsaSigValue` — `ecdsa_sig_value.rs`

```text
ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
```

`new(r: Asn1Integer, s: Asn1Integer) -> Result<Self, Asn1Error>` — both must be
positive. X9.62 requires `1 <= r,s <= n-1`, but `n` is not here, so positivity
is the whole rule and the doc says so. `Display` writes `r, s`.

Tests: round-trip; zero or negative `r` or `s` is `MalformedValue`; a reversed
field order cannot be detected and is not claimed to be.

### 8. `EcNamedCurve` — `ec_named_curve.rs`

An OID table, the shape `AccessMethod` and `KeyPurposeId` use in
`tc_asn1_x509`: a unit struct with `NamedOid` constants, `ALL`, and
`from_oid(&Asn1Oid) -> Option<NamedOid>`.

Entries, name as the specification spells it:

- X9.62 prime curves, `1.2.840.10045.3.1.1` … `.7`: `prime192v1`, `prime192v2`,
  `prime192v3`, `prime239v1`, `prime239v2`, `prime239v3`, `prime256v1`.
- X9.62 characteristic-two curves, `1.2.840.10045.3.0.1` … `.20`: `c2pnb163v1`,
  `c2pnb163v2`, `c2pnb163v3`, `c2pnb176w1`, `c2tnb191v1`, `c2tnb191v2`,
  `c2tnb191v3`, `c2onb191v4`, `c2onb191v5`, `c2pnb208w1`, `c2tnb239v1`,
  `c2tnb239v2`, `c2tnb239v3`, `c2onb239v4`, `c2onb239v5`, `c2pnb272w1`,
  `c2pnb304w1`, `c2tnb359v1`, `c2pnb368w1`, `c2tnb431r1`.
- SEC 2 curves under `1.3.132.0.x`, the 33 that `tc_ec` already ports, each
  named `secp…` or `sect…` as SEC 2 does.

This item is self-contained data and may ship in its own commit, before or
after the rest; item 5's `Display` falls back to the dotted form without it.

Tests, as `AccessMethod` has them: every entry's DER parses to its own dotted
form and `from_oid` finds it again; every OID in the table is distinct; an OID
outside the table gives `None`.

## Vectors

Two fixed vectors, both hand-checkable, to be used in the tests:

**A synthetic prime field**, for items 1–5. `p = 0xFB` (one octet, so every
field element is one octet), `a = 0x01`, `b = 0x02`, base uncompressed at
`04 03 04`, order `0x11`, cofactor `1`:

```text
30 20
   02 01 01                           -- version 1
   30 08                              -- FieldID
      06 07 2a 86 48 ce 3d 01 01      --   id-prime-field
      02 01 fb                        --   p = 251
   30 08                              -- Curve
      04 01 01                        --   a
      04 01 02                        --   b
   04 03 04 03 04                     -- base, uncompressed
   02 01 11                           -- order = 17
   02 01 01                           -- cofactor = 1
```

**An RFC 5915 prime256v1 private key**, for item 6, with the private key 32
octets of `0x11` and the public key an uncompressed point of `0x04` followed by
64 octets of `0x22`:

```text
30 77
   02 01 01
   04 20 11 11 … 11                   -- 32 octets
   a0 0a
      06 08 2a 86 48 ce 3d 03 01 07   -- prime256v1
   a1 44
      03 42 00 04 22 22 … 22          -- 1 + 64 octets of point
```

Do not invent a "real" curve's full explicit parameters for a test; the
synthetic field above exercises every rule and a reader can verify it by eye.

## Verification

From the workspace root:

```bash
cargo fmt -p tc_asn1_x9 --check
cargo clippy -p tc_asn1_x9 --all-targets -- -D warnings
cargo test -p tc_asn1_x9
RUSTDOCFLAGS="-D warnings" cargo doc -p tc_asn1_x9 --no-deps
cargo build --workspace --locked
```

The crate has no features, so there is no feature matrix; it is `no_std` with
`alloc` unconditionally, like its siblings. The new workspace member changes
`Cargo.lock`, which is why the last line is there.

## Acceptance

- `tc_asn1_x9` builds and passes the five commands above with no warnings.
- Both vectors round-trip byte for byte, under `decode` and `decode_der`.
- Every rule in items 1–7 has a test that fails without it.
- `lib.rs` contains only `//!`, `mod` and `pub use`.
- Neither `tc_asn1_x500` nor `tc_asn1_x509` appears in `Cargo.toml`.
- `cargo tree -p tc_asn1_x9` shows exactly one dependency, `tc_asn1`.
