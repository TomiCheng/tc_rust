# tc_cipher_core

Shared cipher abstractions for the `tc_rust` workspace.

The crate provides separate operational and initialization traits for block
ciphers, stream ciphers, and key wrapping:

- `BlockCipher` contains initialized single-block operations and supports
  dynamic dispatch with `dyn BlockCipher<Error = E>`.
- `BlockCipherInit` provides strongly typed initialization parameters and uses
  `CipherDirection::Encrypt` or `CipherDirection::Decrypt` instead of a boolean
  direction flag.
- `StreamCipher` contains the operations used after initialization and supports
  dynamic dispatch with `dyn StreamCipher<Error = E>`.
- `StreamCipherInit` provides strongly typed initialization parameters and is
  used through the concrete cipher type.
- `KeyWrap` uses caller-provided buffers for allocation-free wrapping and
  unwrapping, and supports dynamic dispatch with `dyn KeyWrap<Error = E>`.
- `KeyWrapInit` provides strongly typed initialization with
  `WrapDirection::Wrap` or `WrapDirection::Unwrap`.

This separation allows an initialized implementation to be placed in a trait
object without erasing its algorithm-specific initialization parameter type.

The crate is dependency-free and supports core-only `no_std` without `alloc`.
