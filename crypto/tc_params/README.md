# tc_params

`tc_params` provides shared parameter traits for cryptographic algorithms in
the `tc_rust` workspace. The traits are the primary API: they describe which
values an algorithm needs without requiring callers to use one specific
parameter struct.

The crate is `no_std`, has no dependencies, and does not allocate.

## Trait-first parameters

An algorithm accepts the capabilities it needs. For example, an algorithm
that requires a key and IV can accept any parameter type implementing both
traits:

```rust
use tc_params::{IvParams, KeyParams};

fn inspect<P>(params: &P)
where
    P: KeyParams + IvParams + ?Sized,
{
    assert!(!params.key().is_empty());
    assert!(!params.iv().is_empty());
}
```

Applications can implement those traits directly on their own parameter
types:

```rust
use tc_params::{IvParams, KeyParams};

struct AppParams<'a> {
    key: &'a [u8],
    iv: &'a [u8],
}

impl KeyParams for AppParams<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for AppParams<'_> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}
```

This lets one caller-owned type flow through multiple cipher layers. An
algorithm should depend on the required traits rather than on a convenience
type such as `KeyWithIvRef`.

## Available traits

| Trait | Supplied value |
|-------|----------------|
| `KeyParams` | Cryptographic key bytes |
| `IvParams` | Required initialization-vector bytes |
| `OptionalIvParams` | An optional initialization vector |
| `InitialAadParams` | Associated data supplied during AEAD initialization |
| `SBoxParams` | An algorithm-specific substitution box |
| `TweakParams` | Optional tweak bytes |
| `Rc2Params` | RC2 key and effective key size |
| `Rc5Params` | RC5 key and round count |

These traits expose values but do not decide whether they are valid. The
consuming cipher or mode validates key lengths, IV lengths, round counts,
tweaks, and other algorithm-specific rules during initialization.

## Convenience types

The crate includes a small set of convenience implementations, primarily for
documentation examples, tests, and simple callers:

| Type | Storage |
|------|---------|
| `KeyRef<'a>` | Borrows key bytes |
| `KeyOwned<N>` | Owns a fixed-size key array |
| `KeyWithIvRef<'a>` | Borrows key and IV bytes |
| `KeyWithIvOwned<K, I>` | Owns fixed-size key and IV arrays |

For example:

```rust
use tc_params::{IvParams, KeyParams, KeyWithIvRef};

let key = [0x11_u8; 16];
let iv = [0x22_u8; 12];
let params = KeyWithIvRef::new(&key, &iv);

assert_eq!(params.key(), &key);
assert_eq!(params.iv(), &iv);
```

`KeyWithIvRef` only stores references; it does not copy or own either byte
array. Its lifetime therefore cannot exceed the shorter lifetime of the key
and IV it borrows.

The owned convenience types use fixed-size arrays and still perform no
algorithm-specific validation. Their `Debug` implementations report lengths
without exposing key material.

## Validation

Run the crate tests from the workspace root:

```bash
cargo test -p tc_params --locked
```
