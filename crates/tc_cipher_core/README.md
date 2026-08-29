# tc_cipher_core

Shared cipher abstractions for the `tc_rust` workspace.

The crate currently provides two stream-cipher traits:

- `StreamCipher` contains the operations used after initialization and supports
  dynamic dispatch with `dyn StreamCipher<Error = E>`.
- `StreamCipherInit` provides strongly typed initialization parameters and is
  used through the concrete cipher type.

This separation allows an initialized implementation to be placed in a trait
object without erasing its algorithm-specific initialization parameter type.

The crate is dependency-free and supports `no_std`.
