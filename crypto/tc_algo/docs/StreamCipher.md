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

| Name | OID | Feature | Key bytes | Nonce bytes |
|---|---|---|---|---|
| `CHACHA7539` | none | `chacha` | 32 | 12 |

`CHACHA20` finds it too, and the case of a name does not matter.

## Params

The row takes a `KeyWithIvOwned`, the same type as the block modes with an IV, and any other type is
`InvalidParams`. So is a key or a nonce of another length. It wipes itself when dropped.

## The nonce

- Never encrypt two messages under one key and nonce. They would share a keystream, and the XOR of
  the two ciphertexts is the XOR of the two messages.
- Nothing checks this: `init` takes a key and nonce it has seen before. Keeping them apart is up to
  the caller.
- With random nonces of 12 bytes, stop at 2^32 messages under one key, as with AES-GCM.
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
- One key and nonce covers up to 256 GiB, the limit of the block counter. Beyond it `update` gives
  `DataLength`.
- The keystream starts at block zero. The encryption example in RFC 8439 starts at block one, since
  ChaCha20-Poly1305 keeps block zero for its Poly1305 key, so to match it, skip 64 bytes.
- ChaCha20 is constant time.
