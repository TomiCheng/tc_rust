# Ed448

This crypto-layer crate implements Ed448 and Ed448ph using SHAKE256 from
`tc_keccak`, fixed-width scalar arithmetic from `tc_edwards`, and the existing
448-bit field from `tc_rfc7748`. Secret keys are 57-byte seeds, public keys are
57 bytes, and signatures are 114 bytes.

`sign`/`verify` always take a context, which may be empty and is limited to 255
bytes. `prehash` produces the 64-byte SHAKE256 digest required by Ed448ph;
`sign_prehashed`/`verify_prehashed` apply the prehash domain flag.

The public key is derived internally during signing. Default verification
matches BC's canonical encodings, rejection of small-order public keys and
cofactor clearing. `verify_strict` and `verify_prehashed_strict` additionally
require prime-subgroup A/R and reject identity A. Full and partial public-key
validation are separate APIs.

`cargo test -p tc_ed448 --release --locked` covers all eleven RFC 8032 vectors
mirrored by BC, including prehash/context variants and long messages, as well
as encoding, tampering and context-limit failures. The portable arithmetic
shares the source-level timing contract described in the EC developer guide.
