# Ed25519

RFC 8032 signing belongs in the crypto layer because its definition includes
SHA-512. This crate reuses `tc_sha`, `tc_edwards` scalar/point arithmetic, and
the full fixed-base table in `tc_rfc7748`; it adds no new third-party dependency
to the workspace. Key generation uses the existing `rand_core` contract.

`public_key` and `sign` accept a 32-byte seed. `sign_ctx` uses the Ed25519ctx
domain even for an empty context. `prehash` computes SHA-512, and
`sign_prehashed`/`verify_prehashed` implement Ed25519ph rather than pure Ed25519
on hash bytes. Contexts have a 255-byte maximum.

Signing derives the public key internally; there is no API accepting a
potentially mismatched seed/public-key pair. Secret scalar reduction and
multiply-add use fixed-width words, not variable-length integers. Signing
processes fixed scalar lengths and scans lookup tables fully.

Default verification matches Bouncy Castle: canonical point/scalar encodings,
rejection of small-order public keys, and the cofactored verification equation.
`verify_strict`, `verify_ctx_strict` and `verify_prehashed_strict` additionally
require prime-subgroup A/R and reject identity A. Full and partial public-key
validation are available separately. Neither policy accepts noncanonical
encodings as ZIP-215 does.

`cargo test -p tc_ed25519 --release --locked` covers all ten RFC 8032 vectors
mirrored by BC (including contexts, prehashes and the 1023-byte message), malformed
encodings, signature corruption, domain separation and context limits. All
twelve Taming EdDSA cases from BC test default-policy compatibility, including
mixed-order cases where strict verification deliberately differs.
