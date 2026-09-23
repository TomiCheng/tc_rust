# Work order: `tc_asn1_pkcs` — PKCS #1, #5, #8, #9 and #10

A new crate in the incubator, on top of `tc_asn1`, `tc_asn1_x500` and
`tc_asn1_x509`. It carries the key and certificate-request formats that sit
between an ASN.1 codec and an algorithm implementation: RSA keys and their
signature and encryption parameters, the PKCS#8 private key container, the
password-based derivation parameters, and the certificate signing request.

## Why

`tc_rsa` and `tc_ec` can compute, and `tc_asn1_x509` can describe a
certificate, but nothing in the workspace can read a key file or write a CSR.
Every one of these structures is shared by more than one consumer — PKCS#8
wraps an RSA key and an EC key alike, PKCS#5 parameters appear in PKCS#8 and
in PKCS#12 — so they belong in one crate rather than in each algorithm's.

## Dependencies

```toml
tc_asn1 = "0.1.1"
tc_asn1_x500 = { path = "../tc_asn1_x500" }
tc_asn1_x509 = { path = "../tc_asn1_x509" }
```

`AlgorithmIdentifier`, `SubjectPublicKeyInfo` and `Extensions` come from
`tc_asn1_x509`; `Name` and `Attribute` come from `tc_asn1_x500`. Nothing is
re-implemented here.

**`DigestInfo` already exists in `tc_asn1_x509`.** It is PKCS#1 by origin, but
it is published there and moving it is a breaking change for no gain. Re-export
it from this crate's `lib.rs` (`pub use tc_asn1_x509::DigestInfo;`) so a PKCS#1
consumer finds it, and do not define a second one.

The EC private key format (`ECPrivateKey`, RFC 5915) belongs to `tc_asn1_x9`,
not here. PKCS#8 stores it as opaque `privateKey` octets; this crate never
looks inside them.

## Out of scope

- **PKCS#7** — superseded by CMS, which is its own crate later.
- **PKCS#12** — needs CMS `ContentInfo`; separate work order after CMS.
- **PKCS#11** — not an ASN.1 format.
- Any cryptography: no key validation (`n = p·q` is never checked), no
  primality test, no KDF, no signature verification, no encryption. This crate
  moves octets between ASN.1 and Rust types.
- Algorithm policy: whether an RSA key is long enough, whether a PRF is
  acceptable, whether an iteration count is high enough. That is the caller's.

## Crate conventions

Same as `tc_asn1_x500` and `tc_asn1_x509`, restated because the crate must be
self-sufficient:

- Path `asn1/tc_asn1_pkcs`, package `tc_asn1_pkcs`, picked up by the workspace
  `asn1/*` glob. `description = "PKCS #1, #5, #8, #9 and #10 structures on top of tc_asn1."`
- `#![no_std]`, `extern crate alloc;`, `lib.rs` holds only `//!`, `mod`,
  `pub use`. No `mod.rs`; one file per type, named after it.
- English code, doc comments and test names. LF endings.
- Every public type: a module doc opening with the RFC reference and a
  ` ```text ` ASN.1 block, a type doc with a doctest,
  `#[derive(Clone, Debug, Eq, PartialEq, Hash)]` unless this order says
  otherwise, and `Display` where a useful one-line rendering exists.
- Traits: `DecodeInner`, `Decode`, `Tagged`, `EncodeContent`, `EncodeTagged`,
  `Encode`. Add `DecodeContent` only for a type that actually appears under an
  IMPLICIT tag — in this order that is nothing; do not add it speculatively.
  A CHOICE type gets a private `tag()` and no `Tagged`, as `GeneralName` does.
- Decoding: `Asn1Ref::parse` → `assert_tag` → `children` → `get…` → `end`, and
  the result goes through `new` so construction and decoding enforce the same
  rules. `MalformedValue` for a broken rule, `UnexpectedTag` for a wrong
  identifier, `Truncated` for a missing field, `TrailingData` for an extra one.
- Test names are full sentences stating the property.
- Every public method's doc states constant or variable time. Everything here
  is variable time: `"Variable time: branches only on the encoding structure."`

## Secrets

`RsaPrivateKey`, `PrivateKeyInfo` and `OtherPrimeInfo` hold private key
material. Same policy as the `tc_asn1_x9` work order, so the two crates
behave alike.

- **No `zeroize` dependency, for now.** Erasing the secret octets needs a
  change in `tc_asn1` first: `Asn1Integer` and `Asn1OctetString` expose only
  `as_bytes(&self)`, so nothing outside that crate can wipe them, and the
  orphan rule blocks implementing `Zeroize` for them here. Copying each secret
  into a `Zeroizing<Vec<u8>>` on this side would leave the original values
  unwiped and add a second copy of every prime, which is worse than not
  trying. The tc_asn1 side is tracked as TomiCheng/tc_asn1#3 and is
  deferred; when it ships,
  `RsaPrivateKey`, `OtherPrimeInfo` and `PrivateKeyInfo` get `Zeroize`,
  `ZeroizeOnDrop` and a hand-written `Drop`, and the builders below have to
  change shape because a type with `Drop` cannot be destructured.
- Until then the type docs say plainly that the octets are **not** wiped and
  that the caller owns their lifetime. Do not imply otherwise.
- A mover for the octets: `PrivateKeyInfo::into_private_key(self) -> Asn1OctetString`.
- **Hand-written `Debug`** that redacts the secret fields, for example
  `RsaPrivateKey { modulus: 323, private_exponent: <redacted>, .. }` and
  `PrivateKeyInfo { algorithm: 1.3.101.112, private_key: <redacted, 34 octets>, .. }`.
  The doc says this is a convenience, not a security boundary.
- No `Display` on any of them.
- Test: `Debug` output contains the modulus and not the private exponent.

## Items

Build in this order, one commit per item, `feat(pkcs): …`.

### 1. `Pkcs1Algorithm` — `pkcs1_algorithm.rs`

An OID table, the shape `ExtensionId` and `AccessMethod` use: a unit struct of
`NamedOid` constants, `ALL`, `from_oid`.

Under `1.2.840.113549.1.1`: `.1` rsaEncryption, `.7` id-RSAES-OAEP,
`.8` id-mgf1, `.9` id-pSpecified, `.10` id-RSASSA-PSS, `.4` md5WithRSAEncryption,
`.5` sha1WithRSAEncryption, `.11` sha256WithRSAEncryption,
`.12` sha384WithRSAEncryption, `.13` sha512WithRSAEncryption,
`.14` sha224WithRSAEncryption, `.15` sha512-224WithRSAEncryption,
`.16` sha512-256WithRSAEncryption.

Also the digest OIDs the PSS and OAEP defaults need, since a consumer has to
compare against them: `1.3.14.3.2.26` id-sha1 and `2.16.840.1.101.3.4.2.{4,1,2,3}`
id-sha224/256/384/512.

Tests as `AccessMethod` has them: every entry's DER parses to its own dotted
form and `from_oid` finds it again; every OID is distinct.

### 2. `RsaPublicKey` — `rsa_public_key.rs`

```text
RSAPublicKey ::= SEQUENCE {          -- RFC 8017 A.1.1
    modulus        INTEGER,          -- n
    publicExponent INTEGER }         -- e
```

```rust
pub fn new(modulus: Asn1Integer, public_exponent: Asn1Integer) -> Result<Self, Asn1Error>
pub fn modulus(&self) -> &Asn1Integer
pub fn public_exponent(&self) -> &Asn1Integer
```

Rules: both must be positive. Nothing else — not that `e` is odd, not that
`e < n`, not the size of `n`.

Vector, `n = 323`, `e = 5`:

```text
30 07 02 02 01 43 02 01 05
```

Tests: that vector round-trips; a zero or negative modulus or exponent is
`MalformedValue` on construction and on decoding; a missing or extra field
gives `Truncated` / `TrailingData`; `31` in place of `30` is `UnexpectedTag`.

### 3. `OtherPrimeInfo` and `RsaPrivateKey` — `rsa_private_key.rs`

```text
RSAPrivateKey ::= SEQUENCE {         -- RFC 8017 A.1.2
    version           Version,       -- 0 two-prime, 1 multi-prime
    modulus           INTEGER,       -- n
    publicExponent    INTEGER,       -- e
    privateExponent   INTEGER,       -- d
    prime1            INTEGER,       -- p
    prime2            INTEGER,       -- q
    exponent1         INTEGER,       -- d mod (p-1)
    exponent2         INTEGER,       -- d mod (q-1)
    coefficient       INTEGER,       -- q^-1 mod p
    otherPrimeInfos   OtherPrimeInfos OPTIONAL }

OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
OtherPrimeInfo  ::= SEQUENCE { prime INTEGER, exponent INTEGER, coefficient INTEGER }
```

Both types in one file, as `policy_mappings.rs` holds two.

The version is derived, not stored: it is 1 exactly when `other_prime_infos`
is non-empty, and 0 otherwise. On decoding, a version that disagrees with the
presence of the field is `MalformedValue`, and any version other than 0 or 1 is
`MalformedValue`. `new` does not take a version.

```rust
pub fn new(
    modulus: Asn1Integer, public_exponent: Asn1Integer, private_exponent: Asn1Integer,
    prime1: Asn1Integer, prime2: Asn1Integer,
    exponent1: Asn1Integer, exponent2: Asn1Integer, coefficient: Asn1Integer,
) -> Result<Self, Asn1Error>
pub fn with_other_prime_infos(self, infos: Vec<OtherPrimeInfo>) -> Result<Self, Asn1Error>
pub fn version(&self) -> u8      // 0 or 1, derived
pub fn to_public_key(&self) -> RsaPublicKey
```

Rules: every INTEGER must be positive; an empty `with_other_prime_infos` list
is `MalformedValue` (the field is omitted by passing nothing, not by passing an
empty list — say so in the doc). No arithmetic relation is checked, and the
doc says so in one sentence: this type does not verify that the values form a
key.

Redacted `Debug` per **Secrets**: `modulus` and `public_exponent` print,
everything else prints `<redacted>`.

Vector, a real two-prime key with `p = 17`, `q = 19`, `n = 323`, `e = 5`,
`d = 173`, `dP = 13`, `dQ = 11`, `qInv = 9`:

```text
30 1d
   02 01 00        -- version 0
   02 02 01 43     -- n = 323
   02 01 05        -- e = 5
   02 02 00 ad     -- d = 173, leading 00 because 0xad has its high bit set
   02 01 11        -- p = 17
   02 01 13        -- q = 19
   02 01 0d        -- dP = 13
   02 01 0b        -- dQ = 11
   02 01 09        -- qInv = 9
```

Tests: that vector round-trips and `to_public_key()` equals item 2's vector; a
multi-prime key with one `OtherPrimeInfo` writes version 1 and round-trips;
version 1 without the field and version 0 with it are both `MalformedValue`;
version 2 is `MalformedValue`; a negative value in any position is
`MalformedValue`; an empty `OtherPrimeInfos` on the wire is `MalformedValue`;
the `Debug` output contains the modulus and not the private exponent.

### 4. `RsassaPssParams` and `RsaesOaepParams` — one file each

```text
RSASSA-PSS-params ::= SEQUENCE {      -- RFC 8017 A.2.3
    hashAlgorithm    [0] HashAlgorithm    DEFAULT sha1,
    maskGenAlgorithm [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
    saltLength       [2] INTEGER          DEFAULT 20,
    trailerField     [3] TrailerField     DEFAULT trailerFieldBC }

RSAES-OAEP-params ::= SEQUENCE {      -- RFC 8017 A.2.1
    hashAlgorithm    [0] HashAlgorithm    DEFAULT sha1,
    maskGenAlgorithm [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
    pSourceAlgorithm [2] PSourceAlgorithm DEFAULT pSpecifiedEmpty }
```

**The RFC 8017 module is `DEFINITIONS EXPLICIT TAGS`, so all of these are
EXPLICIT**, not IMPLICIT like most context tags elsewhere in the workspace.
Read them with `get_explicit_default` and write them with `Explicit::new`.

The defaults are exact values, and they must be spelled out because DER omits
a field equal to its default and rejects one written equal to it
(X.690 §11.5, which `get_explicit_default` already enforces):

- `sha1` is `AlgorithmIdentifier { algorithm: 1.3.14.3.2.26, parameters: NULL }`
  — with an explicit NULL, per RFC 4055 §2.1.
- `mgf1SHA1` is `AlgorithmIdentifier { algorithm: id-mgf1, parameters: sha1 }`,
  the sha1 algorithm identifier above as the parameter.
- `saltLength` is 20, `trailerField` is 1.
- `pSpecifiedEmpty` is
  `AlgorithmIdentifier { algorithm: id-pSpecified, parameters: OCTET STRING of length 0 }`.

Expose those four as public constructors or associated functions
(`RsassaPssParams::sha1()`, `::mgf1_sha1()`, `::default_params()`), so a
consumer can compare without rebuilding them by hand.

```rust
pub fn new(
    hash_algorithm: AlgorithmIdentifier,
    mask_gen_algorithm: AlgorithmIdentifier,
    salt_length: Asn1Integer,
    trailer_field: Asn1Integer,
) -> Result<Self, Asn1Error>
```

Rules: `salt_length` is non-negative; `trailer_field` must be 1 — RFC 8017
defines only `trailerFieldBC(1)`, so anything else is `MalformedValue`.

Tests: the all-defaults value encodes to `30 00` and decodes back; each field
written with its default value decodes under BER and is `NotDer` under DER;
a non-default hash algorithm round-trips and forces the `[0]` wrapper to
appear; an IMPLICIT `[0]` (the contents directly under `A0`) is
`UnexpectedTag`; `trailerField` of 2 is `MalformedValue`; a negative salt
length is `MalformedValue`. The same shape of tests for OAEP.

### 5. `PrivateKeyInfo` and `EncryptedPrivateKeyInfo` — one file each

```text
OneAsymmetricKey ::= SEQUENCE {            -- RFC 5958 §2; PKCS#8 is version 0
    version                   Version,     -- v1(0), v2(1)
    privateKeyAlgorithm       AlgorithmIdentifier,
    privateKey                OCTET STRING,
    attributes            [0] IMPLICIT SET OF Attribute OPTIONAL,
    ...,
    [[2: publicKey        [1] IMPLICIT BIT STRING OPTIONAL ]] }

PrivateKeyInfo ::= OneAsymmetricKey        -- RFC 5208 name, v1 only

EncryptedPrivateKeyInfo ::= SEQUENCE {     -- RFC 5958 §3
    encryptionAlgorithm AlgorithmIdentifier,
    encryptedData       OCTET STRING }
```

Implement the RFC 5958 shape under the name `PrivateKeyInfo`; the module doc
explains that RFC 5208's `PrivateKeyInfo` is the version 0 case of the same
SEQUENCE. These two context fields are **IMPLICIT** (RFC 5958's module is
`DEFINITIONS IMPLICIT TAGS`), unlike item 4 — state that in the doc, because
the two neighbouring items disagree and the reader will wonder.

The version is derived as in item 3: 1 exactly when `public_key` is present,
0 otherwise. A version that disagrees is `MalformedValue`; a version other
than 0 or 1 is `MalformedValue`.

```rust
pub fn new(algorithm: AlgorithmIdentifier, private_key: Asn1OctetString) -> Self
pub fn with_attributes(self, attributes: Vec<Attribute>) -> Result<Self, Asn1Error>
pub fn with_public_key(self, public_key: Asn1BitString) -> Self
pub fn version(&self) -> u8
pub fn algorithm(&self) -> &AlgorithmIdentifier
pub fn private_key(&self) -> &Asn1OctetString
pub fn into_private_key(self) -> Asn1OctetString
pub fn attributes(&self) -> &[Attribute]      // empty means the field is absent
pub fn public_key(&self) -> Option<&Asn1BitString>
```

An empty attribute list means the field is omitted; a present but empty
`SET OF` on the wire is `MalformedValue`, as `PolicyInformation` treats its
qualifiers. Read the field with
`get_implicit_opt::<Asn1SetOf<Attribute>>([0xA0])`, which works because
`Asn1SetOf` implements `DecodeContent`.

Redacted `Debug` and no `Display` per **Secrets**.

Vector, the RFC 8410 §7 Ed25519 key shape, with the 32 seed octets
`0x11` — note the doubly wrapped OCTET STRING, which is the format, not a
mistake:

```text
30 2e
   02 01 00
   30 05 06 03 2b 65 70          -- id-Ed25519, no parameters
   04 22 04 20 11 11 … 11        -- OCTET STRING holding CurvePrivateKey
```

`EncryptedPrivateKeyInfo` is a plain two-field SEQUENCE with no rules beyond
the structure; its doc says the octets are ciphertext and this crate neither
decrypts nor recognises the scheme.

Tests: the vector round-trips byte for byte; adding a public key writes
version 1 and an `81` tag; attributes write under `A0` with the SET contents
directly (no inner `31`); a present empty attribute set is `MalformedValue`;
version 1 without a public key is `MalformedValue`; an EXPLICIT `[0]`
(holding a whole `31 …`) is `UnexpectedTag`; the fields out of order give
`TrailingData`.

### 6. `Pkcs5Algorithm`, `PbeParameter`, `Pbkdf2Params`, `Pbes2Params`, `PbMac1Params`

```text
PBEParameter ::= SEQUENCE {           -- RFC 8018 A.3
    salt           OCTET STRING (SIZE(8)),
    iterationCount INTEGER }

PBKDF2-params ::= SEQUENCE {          -- RFC 8018 A.2
    salt           CHOICE {
                       specified   OCTET STRING,
                       otherSource AlgorithmIdentifier },
    iterationCount INTEGER (1..MAX),
    keyLength      INTEGER (1..MAX) OPTIONAL,
    prf            AlgorithmIdentifier DEFAULT algid-hmacWithSHA1 }

PBES2-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier,
                            encryptionScheme  AlgorithmIdentifier }
PBMAC1-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier,
                             messageAuthScheme AlgorithmIdentifier }
```

`Pkcs5Algorithm` is an OID table for `1.2.840.113549.1.5.{12 id-PBKDF2,
13 id-PBES2, 14 id-PBMAC1}` and the PRFs under `1.2.840.113549.2.{7 hmacWithSHA1,
8 hmacWithSHA224, 9 hmacWithSHA256, 10 hmacWithSHA384, 11 hmacWithSHA512}`.

`Pbkdf2Salt` is a small CHOICE enum (`Specified(Asn1OctetString)` /
`OtherSource(AlgorithmIdentifier)`) in `pbkdf2_params.rs`, with a private
`tag()` and no `Tagged`, decoded by matching `04` and `30`.

Rules: `PbeParameter`'s salt is exactly 8 octets and its iteration count is
positive; `Pbkdf2Params`'s iteration count and optional key length are
positive. The default PRF is
`AlgorithmIdentifier { hmacWithSHA1, parameters: NULL }` — with the NULL, as
RFC 8018 B.1.1 writes it — and is read with `get_default`, so a written
default is `NotDer` under DER.

Tests: a PBES2 parameter set with PBKDF2 and AES-CBC round-trips from a fixed
vector; a salt of 7 or 9 octets is `MalformedValue`; a zero iteration count is
`MalformedValue`; the default PRF omitted and written behave as above; an
`otherSource` salt round-trips and is distinguished from a specified one.

### 7. `Pkcs9AttributeType` — `pkcs9_attribute_type.rs`

An OID table under `1.2.840.113549.1.9`: `.1` emailAddress, `.2`
unstructuredName, `.3` contentType, `.4` messageDigest, `.5` signingTime,
`.6` countersignature, `.7` challengePassword, `.8` unstructuredAddress,
`.14` extensionRequest, `.15` smimeCapabilities, `.20` friendlyName,
`.21` localKeyId.

No attribute value types are defined here; `tc_asn1_x500::Attribute` already
carries values as `AttributeValue`. Item 8 provides the one accessor that
matters, for `extensionRequest`.

### 8. `CertificationRequestInfo` and `CertificationRequest` — one file each

```text
CertificationRequestInfo ::= SEQUENCE {     -- RFC 2986 §4
    version       INTEGER { v1(0) },
    subject       Name,
    subjectPKInfo SubjectPublicKeyInfo,
    attributes    [0] IMPLICIT SET OF Attribute }

CertificationRequest ::= SEQUENCE {
    certificationRequestInfo CertificationRequestInfo,
    signatureAlgorithm       AlgorithmIdentifier,
    signature                BIT STRING }
```

`attributes` is **not optional**: the `[0]` field is always present and may
hold an empty SET. Encode it even when empty; a missing `[0]` on decoding is
`Truncated`. This is the one place in the workspace where an empty `SET OF` is
written rather than omitted, so say why in the doc.

The version is not stored: checked to be 0 on decoding, written as 0 always.

```rust
pub fn new(subject: Name, subject_pk_info: SubjectPublicKeyInfo) -> Self
pub fn with_attributes(self, attributes: Vec<Attribute>) -> Result<Self, Asn1Error>
pub fn attributes(&self) -> &[Attribute]
pub fn extension_request(&self, context: &mut DecodingContext)
    -> Result<Option<Extensions>, Asn1Error>
```

`extension_request` finds the `1.2.840.113549.1.9.14` attribute, requires it to
carry exactly one value, and decodes that value as `tc_asn1_x509::Extensions`;
a repeated attribute type or a multi-valued extensionRequest is
`MalformedValue`. It mirrors `Extensions::get_as` in x509 — read that method
first and match its shape.

`CertificationRequest` **keeps the original `certificationRequestInfo`
octets**, exactly as `Certificate`, `CertificateList` and
`AttributeCertificate` do: a `tbs_raw`-style `Vec<u8>` captured with
`fields.peek()` before decoding, written back unchanged on encoding even when
DER is asked for, with `request_info_raw()` as the accessor. Read
`certificate.rs` before writing this one and follow it. The outer
`signatureAlgorithm` is taken from nothing — unlike a certificate, a CSR's
info does not carry its own algorithm, so `new` takes it:

```rust
pub fn new(
    request_info: CertificationRequestInfo,
    signature_algorithm: AlgorithmIdentifier,
    signature: Asn1BitString,
) -> Result<Self, Asn1Error>
```

Tests: a request with an RSA key and no attributes round-trips, with the empty
`a0 00` present in the encoding; a request carrying an extensionRequest
returns the `Extensions` through the accessor and `None` when the attribute is
absent; a BER-encoded request re-encodes its info octets unchanged and is
`NotDer` under `decode_der`; a missing `[0]` is `Truncated`; a version other
than 0 is `MalformedValue`; an extra fourth field is `TrailingData`.

## Verification

```bash
cargo fmt -p tc_asn1_pkcs --check
cargo clippy -p tc_asn1_pkcs --all-targets -- -D warnings
cargo test -p tc_asn1_pkcs
RUSTDOCFLAGS="-D warnings" cargo doc -p tc_asn1_pkcs --no-deps
cargo build --workspace --locked
```

No features; `no_std` with `alloc` unconditionally, like its siblings. The new
workspace member changes `Cargo.lock`, hence the last line.

## Acceptance

- The five commands above pass with no warnings.
- Every vector in items 2, 3, 5 round-trips byte for byte under `decode` and
  `decode_der`.
- Every rule stated above has a test that fails without it.
- `lib.rs` contains only `//!`, `mod` and `pub use` — including the
  `pub use tc_asn1_x509::DigestInfo;` re-export.
- No second `DigestInfo`, `AlgorithmIdentifier`, `Name` or `Attribute` is
  defined in this crate.
- `Debug` for `RsaPrivateKey` and `PrivateKeyInfo` does not contain the secret
  octets, and a test asserts it.
