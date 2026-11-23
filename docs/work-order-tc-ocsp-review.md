# Work order: `tc_ocsp` review fixes

Follow-up to the first `security/tc_ocsp` drop. Three changes, all inside
`security/tc_ocsp`. Do not touch any other crate; if a fix seems to need one,
stop and report (see item 1).

## 1. Test against Bouncy Castle's vectors

The only tests today use messages this crate generated itself. `der()` in
`src/lib.rs` rejects any input that does not re-encode to the same bytes, so a
normalisation difference in `tc_asn1` would reject real responders' messages
without any test noticing.

Source: `D:\github\bc-csharp\crypto\test\src\ocsp\test\OCSPTest.cs`. Read the
file; do not work from memory.

- `testResp1`, `testResp2` (lines ~23 and ~59): `decode_response` →
  `basic_response` succeeds; status is successful; the signature verifies with
  the public key of the first certificate in the response's `certs`, as BC does
  at lines ~745–771. Also check that the response list is non-empty.
- `irregReq` (line ~117): `decode_request` succeeds and
  `verify_request_signature` passes with the public key of the first
  certificate in the request's `certs` (BC `DoTestIrregularVersionReq`). This
  request writes the default version explicitly; `tc_asn1_ocsp` keeps such a
  version, so it should round-trip.
- Put the vectors in `tests/` as base64 or hex constants, with a comment that
  names the BC file they come from.
- If the signature algorithm in a vector is not available through
  `DefaultX509OperatorBuilder`, say which one in the report; do not skip
  silently.

**If a vector fails because re-encoding differs from the input**, do not loosen
`der()` and do not change `tc_asn1` or `tc_asn1_ocsp`. Stop and report which
vector, which field differs, and what fixing it would take (for example, keeping
the raw `tbsResponseData` bytes the way `tc_x509` keeps `tbs_raw`). That is the
user's call.

## 2. `ResponseValidation` without public fields

The repo rule is no `pub` fields on public structs. `ResponseValidation` in
`src/response.rs` has three.

- Private fields.
- `ResponseValidation::new(at: DateTime<Utc>, max_age: TimeDelta)` with no
  nonce.
- `with_expected_nonce(self, nonce: &'a [u8]) -> Self`.
- Getters `at()`, `max_age()`, `expected_nonce()`.
- Keep `Clone, Copy, Debug`.
- Update `tests/ocsp.rs`. It currently mutates `policy.at` and
  `policy.expected_nonce`; build a new value for each case instead, or add
  `with_at` if that reads better. Do not add setters.

## 3. Skip entries whose hash the provider does not support

In `validate`, an entry whose serial matches calls
`certificate_id(certificate, issuer, algorithm.algorithm(), digests)?`. If the
provider does not know that hash, the error ends validation, so a later entry for
the same certificate with a supported hash is never checked.

- If computing the CertID fails because the digest is unknown, skip the entry
  (`continue`), the same way entries with unexpected hash parameters are skipped
  now. Every other error still propagates.
- Find out which error `DigestProvider::calculate_by_oid` returns for an unknown
  OID and match only that error. Do not swallow all `AlgoError`s.
- Duplicate detection stays as it is: two *matching* entries are still an error.
- Test: one response with two entries for the leaf, the first under an OID the
  provider does not know (any unassigned arc), the second under SHA-256.
  `validate` returns the second.

## Minor, same pass

- `OcspError::Crypto` displays as `"OCSP digest error"` but also carries
  signer/verifier errors. Make it `"OCSP crypto error"`.

## Out of scope

- Reshaping the API to follow BC's classes (`OcspReqGenerator`,
  `BasicOcspRespGenerator`, `OcspResp`, `SingleResp`, …). Undecided.
- Clock-skew tolerance, and making `sign_request` accept what `request_for`
  returns.
- Doc comments beyond what changed (incubator rule).

## Done when

- `cargo build -p tc_ocsp` and `cargo test -p tc_ocsp` pass.
- `cargo clippy -p tc_ocsp --all-targets -- -D warnings` is clean.
- Files are LF.
- Do not commit. Report what changed, and the result of each BC vector.
