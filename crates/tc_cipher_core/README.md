# tc_cipher_core

## 1. Overview

`tc_cipher_core` defines the shared cipher contracts used by the `tc_rust`
workspace. It contains traits and direction enums only; concrete algorithms,
parameter types, and error enums belong to downstream crates.

The crate is dependency-free and always supports core-only `no_std`. Its APIs
use caller-provided buffers and do not require `alloc` or `std`. An individual
implementation may still use `alloc` or platform-specific facilities when its
algorithm requires them.

Operational traits are intentionally separated from initialization traits:

```text
concrete type ── implements ── operation trait + initialization trait
                                      │
                                      └── initialized value can use dyn dispatch
```

The operation traits contain no generic associated parameter type, so an
initialized value can be used through a trait object when its error type is
specified:

```rust
&mut dyn BlockCipher<Error = MyError>
&mut dyn StreamCipher<Error = MyError>
&mut dyn KeyWrap<Error = MyError>
```

Callers with `alloc` may also store them in `Box<dyn ...>`.

The initialization traits retain strongly typed, algorithm-specific parameters
through `type Params<'a>`. They are used through the concrete implementation,
before optional conversion to a trait object.

## 2. Trait families

| Family | Operation trait | Initialization trait | Direction |
| --- | --- | --- | --- |
| AEAD cipher | `AeadCipher` | `AeadCipherInit` | `CipherDirection::{Encrypt, Decrypt}` |
| Block cipher | `BlockCipher` | `BlockCipherInit` | `CipherDirection::{Encrypt, Decrypt}` |
| Stream cipher | `StreamCipher` | `StreamCipherInit` | None; the same keystream operation encrypts and decrypts |
| Key wrapping | `KeyWrap` | `KeyWrapInit` | `WrapDirection::{Wrap, Unwrap}` |

### Block cipher traits

`BlockCipher` describes an initialized, fixed-block transformation:

- `algorithm_name()` returns the public algorithm name.
- `block_size()` returns the block size in bytes.
- `process_block()` processes exactly one block and returns the number of bytes
  written.

`BlockCipherInit` selects encryption or decryption and accepts the concrete
algorithm's key, tweak, or other initialization parameters.

### Stream cipher traits

`StreamCipher` describes an initialized keystream generator:

- `return_byte()` processes one byte and advances the keystream.
- `process_bytes()` processes a slice and advances by the same number of bytes.
- `reset()` restores the state established by the most recent initialization.

`StreamCipherInit` accepts the concrete key, nonce, round count, or other
algorithm parameters. It has no encryption boolean because applying the same
keystream operation a second time reverses the transformation.

### AEAD cipher trait

The AEAD family currently provides incremental, caller-buffer operations:

- `AeadCipher::algorithm_name()` returns the public algorithm name.
- `process_aad_bytes()` absorbs associated data without encrypting it.
- `process_bytes()` incrementally processes message data.
- `do_final()` emits or verifies the authentication tag and writes any
  remaining output.
- `mac()` borrows the authentication tag from the last successfully finalized
  operation, or returns `None` when no valid final tag is available.
- `get_update_output_size()` returns the capacity required by one incremental
  update.
- `get_output_size()` returns the capacity required by an update followed by
  finalization.
- `AeadCipherInit::init()` selects encryption or decryption and accepts the
  concrete engine's parameter type.

Decryption may emit unauthenticated plaintext from `process_bytes()` before
`do_final()` verifies the tag. Callers must hold that output until finalization
succeeds.

`AeadCipherInit::Params<'a>` permits borrowed initialization data. The
associated type may also be an unsized parameter trait, allowing one engine to
accept borrowed and owned parameter implementations through the same `init()`
signature. Keeping that GAT out of `AeadCipher` allows initialized engines to
use `dyn AeadCipher<Error = E>`.

### Key-wrapping traits

`KeyWrap` describes an initialized key-wrapping algorithm without allocating
the returned blob:

- `wrapped_len()` returns the exact output length for wrapping an input length.
- `max_unwrapped_len()` returns sufficient output capacity for unwrapping. The
  actual recovered length may only become known after authentication.
- `wrap_into()` protects key material into a caller-provided buffer.
- `unwrap_into()` authenticates and recovers key material into a caller-provided
  buffer.

`KeyWrapInit` selects wrapping or unwrapping and accepts the algorithm-specific
key-encryption key, IV, or other parameters.

## 3. Implementing the traits

Every implementation supplies an associated error type implementing
`core::error::Error`. Invalid keys, invalid input lengths, short buffers,
uninitialized state, wrong operation direction, and integrity failures should
be returned as errors rather than panics.

The following snippets are implementation templates. They assume that
`MyError` and the named algorithm helper functions have been defined by the
downstream crate.

### 3.1 Implementing `BlockCipher`

Store the expanded key and selected direction in the concrete engine. Validate
both buffers before writing anything, process one complete block, and return the
block size.

```rust
use tc_cipher_core::{BlockCipher, CipherDirection};

struct ExampleBlockCipher {
    direction: Option<CipherDirection>,
    round_key: [u8; 16],
}

impl BlockCipher for ExampleBlockCipher {
    type Error = MyError;

    fn algorithm_name(&self) -> &str {
        "Example"
    }

    fn block_size(&self) -> usize {
        16
    }

    fn process_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(MyError::Uninitialised)?;
        if input.len() < 16 || output.len() < 16 {
            return Err(MyError::BufferTooShort);
        }

        match direction {
            CipherDirection::Encrypt => encrypt_block(
                &self.round_key,
                &input[..16],
                &mut output[..16],
            ),
            CipherDirection::Decrypt => decrypt_block(
                &self.round_key,
                &input[..16],
                &mut output[..16],
            ),
        }
        Ok(16)
    }
}
```

`process_block()` may ignore bytes after the first complete block. It must not
silently process a partial block or report success before initialization.

### 3.2 Implementing `BlockCipherInit`

Define a concrete parameter type and use the GAT to allow either owned or
borrowed parameter storage. Validate the parameters and build the complete
working state during `init()`.

```rust
use tc_cipher_core::{BlockCipherInit, CipherDirection};

struct ExampleBlockParams<'a> {
    key: &'a [u8],
}

impl BlockCipherInit for ExampleBlockCipher {
    type Params<'a> = ExampleBlockParams<'a>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        if params.key.len() != 16 {
            return Err(MyError::InvalidKeyLength);
        }

        self.round_key.copy_from_slice(params.key);
        self.direction = Some(direction);
        Ok(())
    }
}
```

After initialization, the value can be used through `dyn BlockCipher` because
the operation trait does not expose `Params<'a>`.

### 3.3 Implementing `StreamCipher`

`return_byte()` and `process_bytes()` must consume the same keystream in the
same order. Check the complete output capacity and any algorithm usage limits
before modifying state so a rejected call does not partially advance the
cipher.

```rust
use tc_cipher_core::StreamCipher;

impl StreamCipher for ExampleStreamCipher {
    type Error = MyError;

    fn algorithm_name(&self) -> &str {
        "ExampleStream"
    }

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        let key_byte = self.next_key_byte()?;
        Ok(input ^ key_byte)
    }

    fn process_bytes(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        if output.len() < input.len() {
            return Err(MyError::BufferTooShort);
        }

        for (input, output) in input.iter().zip(output.iter_mut()) {
            *output = self.return_byte(*input)?;
        }
        Ok(input.len())
    }

    fn reset(&mut self) {
        self.state = self.initial_state;
    }
}
```

`reset()` is infallible and must restore the nonce, counter, and internal state
created by the most recent successful initialization.

### 3.4 Implementing `StreamCipherInit`

The parameter type normally contains a key and nonce and may also carry a round
count or algorithm variant. Initialization validates them and stores enough
state for `reset()`.

```rust
use tc_cipher_core::StreamCipherInit;

struct ExampleStreamParams<'a> {
    key: &'a [u8],
    nonce: &'a [u8],
}

impl StreamCipherInit for ExampleStreamCipher {
    type Params<'a> = ExampleStreamParams<'a>;

    fn init(&mut self, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        validate_key_and_nonce(params.key, params.nonce)?;
        self.initial_state = make_initial_state(params.key, params.nonce);
        self.state = self.initial_state;
        Ok(())
    }
}
```

### 3.5 Implementing `KeyWrap`

Sizing methods must validate the input length and use checked arithmetic.
`wrapped_len()` is exact; `max_unwrapped_len()` may be conservative when the
actual key length is stored inside the authenticated blob.

```rust
use tc_cipher_core::{KeyWrap, WrapDirection};

impl KeyWrap for ExampleKeyWrap {
    type Error = MyError;

    fn algorithm_name(&self) -> &str {
        "ExampleWrap"
    }

    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len < 8 || !input_len.is_multiple_of(8) {
            return Err(MyError::InvalidInputLength);
        }
        input_len.checked_add(8).ok_or(MyError::InvalidInputLength)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len < 16 || !input_len.is_multiple_of(8) {
            return Err(MyError::InvalidInputLength);
        }
        input_len.checked_sub(8).ok_or(MyError::InvalidInputLength)
    }

    fn wrap_into(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        self.require_direction(WrapDirection::Wrap)?;
        let required = self.wrapped_len(input.len())?;
        if output.len() < required {
            return Err(MyError::BufferTooShort);
        }

        wrap_core(&mut self.engine, input, &mut output[..required])?;
        Ok(required)
    }

    fn unwrap_into(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        self.require_direction(WrapDirection::Unwrap)?;
        let capacity = self.max_unwrapped_len(input.len())?;
        if output.len() < capacity {
            return Err(MyError::BufferTooShort);
        }

        let written = unwrap_and_authenticate(
            &mut self.engine,
            input,
            &mut output[..capacity],
        )?;
        Ok(written)
    }
}
```

`unwrap_into()` must complete the format's integrity checks before reporting
success. If temporary plaintext is written before authentication finishes, it
must be cleared before returning an integrity error so unauthenticated key
material is not left in the caller's buffer.

The core trait does not select or obtain randomness. A wrapper that needs a
random IV or padding must expose that requirement explicitly through its
concrete API rather than silently sourcing global entropy.

### 3.6 Implementing `KeyWrapInit`

Initialize the underlying primitive in the direction required by the wrapping
format. `WrapDirection` describes the key-level operation; it is not always the
same as the underlying block cipher's encryption direction.

```rust
use tc_cipher_core::{KeyWrapInit, WrapDirection};

struct ExampleWrapParams<'a> {
    key_encryption_key: &'a [u8],
    iv: [u8; 8],
}

impl KeyWrapInit for ExampleKeyWrap {
    type Params<'a> = ExampleWrapParams<'a>;

    fn init(
        &mut self,
        direction: WrapDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        validate_kek(params.key_encryption_key)?;
        self.initialize_engine(direction, params.key_encryption_key)?;
        self.iv = params.iv;
        self.direction = Some(direction);
        Ok(())
    }
}
```

Initialization parameters are borrowed only for the call. Implementations
should copy or expand the required key, IV, nonce, and tweak material into their
own working state rather than retaining references to the parameter object.
