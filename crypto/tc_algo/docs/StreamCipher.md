# Stream ciphers

A stream cipher turns a key and a nonce into a keystream, and XORs the message with it. There are no
blocks and no padding, so the ciphertext is exactly as long as the message.

From a new key to the decrypted message, with ChaCha20. The `chacha` feature of `tc_algo` has the
row, and the nonce here comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::params::{KeyLength, KeyOwned, KeyParams, KeyWithIvOwned};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "CHACHA7539";
    let message = b"attack at dawn";

    // Generate a key
    let key = algo
        .key_generator()
        .generate_by_name_with("KEY", &KeyLength::new(32))?;
    let key = key
        .as_any()
        .downcast_ref::<KeyOwned>()
        .expect("KEY generates a KeyOwned");

    // Set a new nonce
    let mut nonce = vec![0; 12];
    UnwrapErr(SysRng).fill_bytes(&mut nonce);
    let params = KeyWithIvOwned::new(key.key().to_vec(), nonce);

    // Encrypt
    let ciphertext = algo.cipher().encrypt_by_name(name, &params, message)?;

    // Decrypt
    let plaintext = algo.cipher().decrypt_by_name(name, &params, &ciphertext)?;

    assert_eq!(plaintext, message);
    Ok(())
}
```

## Algorithms

| Name | Aliases | OID | Feature | Key bytes | Nonce bytes | Note |
|---|---|---|---|---|---|---|
| `CHACHA7539` | `CHACHA20` |  | `chacha` | 32 | 12 |  |
| `CHACHA` |  |  | `chacha` | 16, 32 | 8 |  |
| `XCHACHA20` |  |  | `xchacha20` | 32 | 24 |  |
| `SALSA20` |  |  | `salsa20` | 16, 32 | 8 |  |
| `XSALSA20` |  |  | `xsalsa20` | 32 | 24 |  |
| `HC128` |  |  | `hc128` | 16 | 16 | variable time |
| `HC256` |  |  | `hc256` | 16, 32 | 16 to 32 | variable time |
| `ARC4` | `RC4`, `ARCFOUR` | `1.2.840.113549.3.4` | `rc4` | 1 to 256 | none | weak, variable time |
| `VMPC` | `VMPC-MAC` |  | `vmpc` | 16 to 64 | 16 to 64 | variable time |
| `VMPC-KSA3` |  |  | `vmpc-ksa3` | 16 to 64 | 16 to 64 | variable time |
| `ISAAC` |  |  | `isaac` | up to 1024 | none | variable time |

The names, aliases and OID are those of Bouncy Castle's `CipherUtilities`, and the case of a name
does not matter. `XSALSA20` and `ISAAC`, which Bouncy Castle has as engines but not there, are named
after them, with no alias or OID. `CHACHA7539` is ChaCha20 of RFC 8439; `CHACHA` is the original
ChaCha20, with a nonce of 8 bytes and a counter of 8.

- **ARC4 is weak**: the start of its keystream leans toward some values, which leaks the message,
  and it takes no nonce, so a key must never be used twice. It is here for old data only.
- **A variable-time cipher** looks up tables by bytes of its state, so it can leak through cache
  timing to code that shares the processor. ChaCha20 and Salsa20 are constant time.
- ChaCha20-Poly1305 and XChaCha20-Poly1305 are AEAD ciphers, not rows here.

## Params

`ARC4` and `ISAAC` take a `KeyOwned`, a key alone; the others take a `KeyWithIvOwned`, a key and a
nonce, the same type as the block modes with an IV. Any other type is `InvalidParams`, as is a key
or a nonce of a length the table does not give. Both wipe themselves when dropped.

## The nonce

- Never encrypt two messages under one key and nonce. They would share a keystream, and the XOR of
  the two ciphertexts is the XOR of the two messages.
- Nothing checks this: `init` takes a key and nonce it has seen before. Keeping them apart is up to
  the caller.
- With random nonces of 12 bytes, stop at 2^32 messages under one key, as with AES-GCM. A nonce of
  24 bytes, as XChaCha20 and XSalsa20 take, can be drawn at random without that limit.
- The nonce is not secret: send it along with the ciphertext, since decrypting needs the same one.

## Using it

- **It does not detect a changed ciphertext.** Flipping a bit of the ciphertext flips the same bit of
  the plaintext, and decrypting succeeds. To protect a message, use an AEAD cipher, or authenticate
  the ciphertext before decrypting it.
- A message can come in pieces, over several calls of `update`. Each gives as much as it takes, and
  `finalize` gives nothing.
- `update` and `finalize` give `NotInitialized` before an `init` that succeeded.
- `finalize` restarts the keystream, as in Bouncy Castle. So give each message a new `init` with a
  new nonce: a second message without one repeats the keystream, and nothing reports it.
- For `CHACHA7539`, one key and nonce covers up to 256 GiB, the limit of its block counter.
  Beyond it `update` gives `DataLength`.
- The keystream starts at block zero. The encryption example in RFC 8439 starts at block one, since
  ChaCha20-Poly1305 keeps block zero for its Poly1305 key, so to match it, skip 64 bytes.
- ChaCha20 and Salsa20 are constant time; the table gives the others.
