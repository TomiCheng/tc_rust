# tc_binpoly

`tc_binpoly` implements binary-polynomial arithmetic over `GF(2)`, ported from
Bouncy Castle C#'s `crypto/src/math/binpoly` subsystem.

Values use little-endian `u64` limbs: bit `i` is the coefficient of `x^i`.
The crate supports multiplication, squaring, repeated squaring, and
Itoh-Tsujii inversion with binomial, trinomial, and pentanomial reduction.

## Example

```rust
use tc_binpoly::{BinaryPoly, BinPolyMultiplier};

let field = BinPolyMultiplier::trinomial(113, 9)?;
let a = BinaryPoly::from_limbs(field.clone(), vec![0x1234, 0x55])?;
let one = BinaryPoly::one(field);

assert_eq!(a.multiply(&one)?, a);
assert_eq!(a.multiply(&a.invert()?)?, one);
# Ok::<(), tc_binpoly::BinPolyError>(())
```

For an allocation-free value representation, make the limb count part of the
type. Its extended product scratch is `[[u64; N]; 2]` on the stack:

```rust
use tc_binpoly::{BinPolyMultiplier, FixedBinaryPoly};

let field = BinPolyMultiplier::trinomial(113, 9)?;
let a = FixedBinaryPoly::<2>::from_limbs(field.clone(), [0x1234, 0x55])?;
let one = FixedBinaryPoly::<2>::one(field)?;

assert_eq!(a.multiply(&one)?, a);
# Ok::<(), tc_binpoly::BinPolyError>(())
```

## Modulus constraints

- `binomial(n)` accepts `1 <= n <= 2^20` and reduces by `x^n + 1`.
- `trinomial(n, k)` additionally requires `n >= 3` and `0 < k < n`.
- `pentanomial(n, k1, k2, k3)` additionally requires `n >= 5` and
  `0 < k1 < k2 < k3 < n`.

Factories validate ranges and tap ordering, but do not prove irreducibility.
Callers using inversion attest that a trinomial or pentanomial is irreducible.
Binomial inversion is rejected because `x^n + 1` is always reducible over
`GF(2)`.

## Allocation and backend selection

The crate is `no_std` and uses `alloc` only for `BinaryPoly` and large dynamic
scratch buffers. Scratch up to 128 limbs stays on the stack. On x86/x86_64,
the factory detects PCLMULQDQ once and stores its proof token in the multiplier
enum; multiplication does not repeat feature detection. Use `force-scalar` to
test or benchmark the portable backend.

`FixedBinaryPoly<N>` performs its arithmetic without heap allocation. Choose
`N = (n + 63) / 64`; excessively large `N` values can consume substantial
stack space.

## Security

Temporary products and inversion buffers are actively erased with volatile
writes plus a compiler fence. Ordinary `zero` remains a separate value-level
operation.

The scalar 16-entry multiplication table uses secret-dependent table indices
and therefore has a cache-timing side channel. Prefer the PCLMULQDQ backend
when the threat model includes local cache-timing attackers. No API in this
crate should yet be assumed to provide a formally verified constant-time
contract.

## Verification

```bash
cargo test -p tc_binpoly --locked
cargo test -p tc_binpoly --features force-scalar --locked
cargo clippy -p tc_binpoly --all-targets --locked -- -D warnings
cargo doc -p tc_binpoly --no-deps --locked
cargo bench -p tc_binpoly --bench baseline
```
