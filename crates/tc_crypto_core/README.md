# tc_crypto_core

Core cryptographic traits shared by the algorithm crates in this workspace.
The crate is dependency-free, always supports `no_std`, and does not require
`alloc`.

This is a learning project and has not been independently audited. Do not use
it for production cryptography.

## Available traits

| Trait | Purpose |
| --- | --- |
| `TryDigest` | Fallible streaming fixed-output digest API. |
| `Digest` | Infallible convenience API for `TryDigest<Error = Infallible>`. |
| `TryXof` | Fallible extendable-output API; extends `TryDigest`. |
| `Xof` | Infallible convenience API for `TryXof<Error = Infallible>`; also a `Digest`. |
| `Mac` | Object-safe streaming message-authentication-code API. |
| `MacInit` | Strongly typed initialization for `Mac`. |

The trait relationships are:

```text
TryDigest
├── Digest          when Error = Infallible
└── TryXof
    └── Xof          when Error = Infallible; also implements Digest
```

`TryDigest` and `TryXof` are the implementation traits. `Digest` and `Xof` are
blanket-implemented convenience traits, so algorithm authors should not
implement them directly.

## Digest traits

`TryDigest` models a streaming fixed-output message digest. Its mutating
operations return `Result` so the same interface can support software hashes,
hardware accelerators, HSMs, or remote services.

```rust
pub trait TryDigest {
    type Error: core::error::Error;

    fn algorithm_name(&self) -> &str;
    fn digest_size(&self) -> usize;
    fn byte_length(&self) -> usize;

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error>;
    fn try_update_byte(&mut self, input: u8) -> Result<(), Self::Error>;
    fn try_do_final(&mut self, output: &mut [u8])
        -> Result<usize, Self::Error>;
    fn try_reset(&mut self) -> Result<(), Self::Error>;
}
```

`try_do_final` writes `digest_size()` bytes and leaves the digest reset for a
new message.

Pure-software implementations normally use `core::convert::Infallible` as the
error type. They then receive the `Digest` methods automatically:

```rust
pub trait Digest: TryDigest<Error = core::convert::Infallible> {
    fn update(&mut self, input: &[u8]);
    fn update_byte(&mut self, input: u8);
    fn do_final(&mut self, output: &mut [u8]) -> usize;
    fn reset(&mut self);
}
```

## XOF traits

An XOF absorbs a message and then squeezes a caller-selected number of output
bytes. `TryXof` extends `TryDigest`, so every XOF also has a default fixed output
length through `try_do_final` and `digest_size`.

```rust
pub trait TryXof: TryDigest {
    fn try_output(&mut self, output: &mut [u8])
        -> Result<usize, Self::Error>;
    fn try_output_final(&mut self, output: &mut [u8])
        -> Result<usize, Self::Error>;
}
```

For `Error = Infallible`, the blanket implementation supplies:

```rust
pub trait Xof: TryXof<Error = core::convert::Infallible> + Digest {
    fn output(&mut self, output: &mut [u8]) -> usize;
    fn output_final(&mut self, output: &mut [u8]) -> usize;
}
```

The two output operations have different reset behavior:

| Operation | Behavior |
| --- | --- |
| `output` / `try_output` | Starts or continues squeezing; does not reset. |
| `output_final` / `try_output_final` | Squeezes the requested bytes, then resets. |
| `do_final` / `try_do_final` | Produces the default digest length, then resets. |

Consecutive `output` calls continue the same byte stream. For example, asking
for 16 bytes and then 32 bytes is equivalent to asking for 48 bytes once.
After squeezing starts, callers must reset before absorbing another message.

```rust
use tc_crypto_core::{Digest, Xof};

fn read_xof(xof: &mut impl Xof, message: &[u8]) -> [u8; 48] {
    xof.update(message);

    let mut output = [0u8; 48];
    xof.output(&mut output[..16]);
    xof.output_final(&mut output[16..]);
    output
}
```

## MAC traits

`Mac` contains the operations used after initialization and supports dynamic
dispatch. `MacInit` is separate so implementations can use strongly typed,
possibly borrowed initialization parameters without making `Mac` depend on a
generic associated type.

```rust
pub trait Mac {
    type Error: core::error::Error;

    fn algorithm_name(&self) -> &str;
    fn mac_size(&self) -> usize;
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;
    fn do_final(&mut self, output: &mut [u8])
        -> Result<usize, Self::Error>;
    fn reset(&mut self);
}

pub trait MacInit: Mac {
    type Params<'a>: ?Sized;

    fn init(&mut self, params: &Self::Params<'_>)
        -> Result<(), Self::Error>;
}
```

A successful `do_final` resets the accumulated message while retaining the
state established by the most recent `init` call.

## Implementing an algorithm

- A fixed-output software digest implements `TryDigest<Error = Infallible>`.
- A fallible fixed-output backend implements `TryDigest` with its own error.
- A software XOF implements both `TryDigest<Error = Infallible>` and `TryXof`.
- A fallible XOF implements both `TryDigest` and `TryXof` with the same error
  type inherited from `TryDigest`.

The blanket implementations then provide `Digest` and/or `Xof` automatically.
