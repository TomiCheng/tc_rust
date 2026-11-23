# Work order: `tc_crmf` — RFC 4211 certificate request messages

A new crate, `security/tc_crmf`, porting Bouncy Castle C#'s `Org.BouncyCastle.Crmf`
(`D:\github\bc-csharp\crypto\src\crmf`, baseline `4814a10b`). The ASN.1 types
already exist in `tc_asn1_cmp::crmf`; this crate adds the operations: building
and signing request messages, proof of possession, the password-based MAC
(PKMAC) and registration controls.

Read each BC file before porting it; do not work from memory. Follow BC's
structure: one Rust type per BC class (`CertificateRequestMessage`,
`CertificateRequestMessageBuilder`, `PkMacBuilder`, …), the same way `tc_cms`
follows `Org.BouncyCastle.Cms`.

Two batches. **Stop after batch A** and report; batch B starts after review.

## Crate conventions

- Path `security/tc_crmf`, package `tc_crmf`. Cargo.toml like `tc_ocsp`'s:
  workspace version/edition/license/repository, `rust-version = "1.85"`,
  `description = "CRMF certificate request messages, after Bouncy Castle C#'s Org.BouncyCastle.Crmf."`.
- Dependencies: `tc_asn1_cmp` (path), `tc_asn1`, `tc_asn1_x509`, `tc_asn1_x500`,
  `tc_x509` (path), `tc_algo` (path), `tc_zeroize`. Batch B adds `tc_cms` and
  `tc_asn1_pkcs`. Enable only the `tc_algo` features this crate actually uses.
- `lib.rs` holds only `//!`, `mod` and `pub use`. No `mod.rs`. No `pub` fields on
  public structs: private fields with `new`, `with_…`/`set_…` and getters.
- Library code returns errors, never panics on input. Define `CrmfError`
  (`#[non_exhaustive]`) wrapping the upstream errors (`Asn1Error`, `AlgoError`,
  `X509Error`, later `CmsError`) plus its own variants. Do not add variants to
  upstream crates.
- Do not change any other crate. If something upstream is missing, stop and
  report what and where.
- Incubator: short docs only, no long comments.
- Test names are full sentences describing the property checked.
- Files LF.

## Batch A — requests, POP, PKMAC, controls

### `PkMacBuilder` (BC `PKMacBuilder`, `IPKMacPrimitivesProvider`, `DefaultPKMacPrimitivesProvider`)

- Defaults as BC: OWF SHA-1 (`1.3.14.3.2.26`), MAC HMAC-SHA1
  (`1.3.6.1.5.5.8.1.2` with NULL parameters), 1000 iterations, 20-byte salt.
- `with_salt_length` (minimum 8), `with_iteration_count` (minimum 100),
  `with_parameters(PbmParameter)`, `with_max_iterations`.
- Digests and MACs come from `tc_algo`'s `DigestProvider` / `MacProvider` by OID;
  that replaces BC's primitives provider. The RNG is passed in the way `tc_cms`
  does it.
- Iteration ceiling exactly as BC's `CheckIterationCount`: reject values outside
  `i32`, below 1, or above the ceiling; the ceiling defaults to 1 000 000 when
  none is set. This applies to `PbmParameter`s read from incoming messages —
  it is the DoS guard.
- Key derivation as RFC 4211 §4.4 / BC `GenCalculator`: `K = H(pw || salt)`,
  hashed `iter − 1` more times, then HMAC with `K` as key. Password is `&str`,
  encoded UTF-8 (as `tc_cms::enveloped::PasswordKey`). Zeroize `pw || salt` and
  `K` after use.
- `build(password)` (fresh random salt) and `get(algorithm, password)` (from
  an incoming `AlgorithmIdentifier` whose OID must be `CrmfId::PASSWORD_BASED_MAC`).
- `PkMacValueGenerator` / `PkMacValueVerifier`: MAC over the DER of a
  `SubjectPublicKeyInfo`. Compare MACs in constant time.

### `ProofOfPossessionSigningKeyBuilder`

As BC: from a `CertRequest` (signature over the `CertRequest`) or from a
`SubjectPublicKeyInfo` (signature over `POPOSigningKeyInput`, with either
`sender` or `publicKeyMAC`). `build(&dyn SignatureFactory)` → `PopoSigningKey`.
Missing sender/MAC in the second form is an error, as BC.

### `CertificateRequestMessageBuilder`

- Every setter in BC's `CertificateRequestMessageBuilder` (template fields,
  extensions, controls, regInfo, the POP choices, authInfo sender / PKMAC).
- Setting a second proof of possession returns an error. BC's checks are
  slightly asymmetric (for example `SetProofOfPossessionRaVerified` does not
  check `agreeMac`); make every POP setter reject any earlier one, and note this
  in the report.
- `build()` follows BC's `Build()` exactly, including the RFC 4211 §4.1 checks
  (signing-key POP needs a public key in the template; without a subject it
  needs a sender or PKMAC) and the RA-verified POP when no POP was set.

### `CertificateRequestMessage`

- `decode(der)`, `encode()`, `from(CertReqMsg)`, `to_asn1()`.
- Getters as BC: `cert_req_id`, `cert_template`, controls, POP type.
- `has_signing_key_pop_with_pk_mac` as BC: a total predicate, `false` rather
  than an error when POP or `poposkInput` is absent.
- `is_valid_signing_key_pop(&dyn VerifierFactoryProvider)` and
  `is_valid_signing_key_pop_with_mac(provider, &PkMacBuilder, password)`. The
  cases BC throws `InvalidOperationException` for (wrong POP type, PKMAC
  required / absent) are errors; a signature or MAC that does not verify is
  `Ok(false)`, as BC.
- The signature is checked over the encoding of `poposkInput` when present,
  otherwise the `CertRequest` — over the bytes as received, not a re-encoding.
  If `tc_asn1_cmp` does not keep the raw bytes, decoding must reject
  non-canonical DER (the way `tc_ocsp`'s `der()` does); report which you chose.

### Controls (BC `IControl` and the six control classes)

One enum `Control` instead of the interface: `RegToken`, `Authenticator`,
`PkiPublicationInfo`, `PkiArchive`, `OldCertId`, `ProtocolEncrKey`, each holding
its ASN.1 value, with `oid()`. `CertificateRequestMessage::control(oid)` decodes
the matching `AttributeTypeAndValue` into it, as BC's `GetControl`. In batch A,
`PkiArchive` holds the `PkiArchiveOptions` only; its enveloped-data accessor
comes in batch B.

### `CertificateReqMessages`, `CertificateReqMessagesBuilder`

As BC, including `from_pki_body` / `is_certificate_request_messages` over
`tc_asn1_cmp::PkiBody`.

### Tests (batch A)

From `D:\github\bc-csharp\crypto\test\src\crmf\test\CrmfTest.cs`:

- `MessageFromJVM`: the RSA public key and message hex, POP verifies; flipping
  byte 7 makes it fail.
- `PKMacIterationCountCeiling`, `PKMacIterationCountNegative`,
  `PKMacIterationCountOutsideInt32`.
- `BasicMessage`, `BasicMessageWithOldCertIDControl`,
  `BasicMessageWithProtocolEncrKeyControl`, `BasicMessageWithPublicationInfoControl`,
  `BasicMessageWithRegInfo`, `GetControlValue`, `ProofOfPossessionWithSender`,
  `ProofOfPossessionWithoutSender` (PKMAC path, wrong password fails),
  `HasSigningKeyPopWithPKMacIsTotal`, `ProofOfPossessionWithTemplate`,
  `ProofOfPossessionSigningKeyIncomplete`.

Use Ed25519 or RSA keys from `tc_x509`'s operator, whichever the BC test needs.
If a BC test depends on something batch A does not cover, list it in the report.

## Batch B — archive control, encrypted value, responses (after review)

- `PkiArchiveControlBuilder` / `PkiArchiveControl`: `PrivateKeyInfo` wrapped in
  CMS EnvelopedData via `tc_cms::enveloped` recipient generators;
  `is_enveloped_data`, `enveloped_data()`. Tests `BasicMessageWithArchiveControl`,
  `ECBasicMessageWithArchiveControl`, `ArchiveControlWithoutEnvelopedData`.
- `EncryptedValueBuilder` with `IEncryptedValuePadder`: key wrap of the content
  key to the recipient's public key plus symmetric encryption, through
  `tc_algo`. Test `EncryptedValueWithKey`, and decrypt the result in the test to
  check the round trip (BC's own test cannot).
- `CertificateResponse`, `CertificateResponseBuilder`, `CertificateRepMessage`,
  `CertificateRepMessageBuilder` over `tc_asn1_cmp`, with the encrypted
  certificate path through `tc_cms`.

The design for how the key wrapper and content encryptor are passed in is part
of batch B's report: propose it before writing it if it needs new traits.

## Out of scope

- `EncryptedValueParser`: BC C# leaves it as a stub (`NotSupportedException`,
  `TODO[crmf]`). Do not port it.
- `Org.BouncyCastle.Cmp` (`ProtectedPkiMessage` etc.) — separate crate later.
- Obsolete BC methods (`SetAuthInfoPKMAC`).

## Done when (each batch)

- `cargo build -p tc_crmf`, `cargo test -p tc_crmf` pass.
- `cargo clippy -p tc_crmf --no-deps --all-targets -- -D warnings` is clean
  (`--no-deps` because `tc_algo` has unrelated clippy failures).
- Do not commit. Report what was ported, every deviation from BC, and each BC
  test's result.
