# tc_bigint_old

`tc_bigint_old` provides the workspace's signed arbitrary-precision [`BigInt`]
implementation. It was ported from Bouncy Castle C# as a learning project.

The crate supports arithmetic, bitwise operations, shifts, arbitrary-radix text,
big- and little-endian byte/word conversion, modular arithmetic, and
probable-prime operations.

## Example

```rust
use tc_bigint_old::BigInt;

let base = BigInt::from_u32(4);
let exponent = BigInt::from_u32(13);
let modulus = BigInt::from_u32(497);

assert_eq!(
    base.mod_pow(&exponent, &modulus),
    BigInt::from_u32(445),
);

let value = BigInt::from_bytes_be_unsigned(&[0x01, 0x00]);
assert_eq!(value, BigInt::from_u32(256));
assert_eq!(value.to_bytes_le_unsigned(), [0x00, 0x01]);
```

## Runtime requirements

`BigInt` requires `alloc` for dynamically sized storage but does not require
the standard library. Disable the default `std` feature for a `no_std + alloc`
build:

```bash
cargo build -p tc_bigint_old --no-default-features --locked
```

The internal magnitude uses `u64` limbs on 64-bit targets and `u32` limbs on
other pointer widths. Limbs are stored most-significant first. Byte conversion
is explicit, so results do not depend on the target's native endianness.

## Security

This implementation is not promised to be constant-time. General arithmetic,
modular inversion, modular exponentiation, and probable-prime operations must
not be assumed safe for secret-dependent production cryptography.

## Verification

```bash
cargo test -p tc_bigint_old --locked
cargo build -p tc_bigint_old --no-default-features --locked
cargo test -p tc_bigint_old --target i686-pc-windows-msvc --locked
cargo bench -p tc_bigint_old --bench mod_pow
```
