# Naccache-Stern

Naccache-Stern is an encryption whose ciphertexts can be added: the product of two ciphertexts
decrypts to the sum of their messages, modulo `σ`, the product of the small primes of the key. A
message is a number below `σ`. It is built like RSA, on a modulus `n` of two secret primes, but each
of those primes is one more than a product of many small primes.

The `naccache-stern` feature of `tc_algo` has the rows. The keys and the params are in
`tc_algo::params`.

## Key pairs

From the params to a new pair:

```rust
use tc_algo::params::{
    generate::NaccacheSternKeyGenerationParams, key::naccache_stern::NaccacheSternPrivateKey, key::naccache_stern::NaccacheSternPublicKey,
};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 768-bit n, a certainty of 8 and 30 small primes, as in Bouncy Castle's tests
    let params = NaccacheSternKeyGenerationParams::new(768, 8, 30);

    // Generate the pair
    let pair = algo.key_pair_generator().generate_by_name_with("NACCACHESTERN", &params)?;

    // One key is a NaccacheSternPublicKey, the other a NaccacheSternPrivateKey
    let public = pair.public().as_any().downcast_ref::<NaccacheSternPublicKey>();
    let private = pair.private().as_any().downcast_ref::<NaccacheSternPrivateKey>();
    assert!(public.is_some() && private.is_some());
    Ok(())
}
```

### Algorithms

| Name | OID | Feature | Params | Public key | Private key |
|---|---|---|---|---|---|
| `NACCACHESTERN` | none | `naccache-stern` | `NaccacheSternKeyGenerationParams` | `NaccacheSternPublicKey` | `NaccacheSternPrivateKey` |

Bouncy Castle has the generator but no name for it in `GeneratorUtilities`, so the name is this
crate's, that of the engine. The case of the name does not matter.

### Params

The row takes a `NaccacheSternKeyGenerationParams`, and any other type is `InvalidParams`.
`new(strength, certainty, count_small_primes)` holds:

| Argument | What it is |
|---|---|
| `strength` | the size of `n` in bits |
| `certainty` | how sure the prime tests are, at least 1 |
| `count_small_primes` | how many small primes make up `σ` |

`init` has `tc_naccache_stern` judge these, so a bad set, such as a `strength` too small for the
count of small primes, is `InvalidParams` there.

### Using it

- `NACCACHESTERN` has no default, so it needs `init`: `generate_by_name_with`, or `get_by_name`,
  `init` and `generate`. `generate_by_name` gives `NotInitialized`.
- Generating a key is slow, and its time varies with how many candidates it tries.
- The keys draw from the source of `DefaultAlgoBuilder::set_rand`.

## Encrypting

From a new pair to the decrypted message:

```rust
use tc_algo::params::generate::NaccacheSternKeyGenerationParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let message = [0x01, 0x23];

    // Generate a pair
    let params = NaccacheSternKeyGenerationParams::new(768, 8, 30);
    let pair = algo.key_pair_generator().generate_by_name_with("NACCACHESTERN", &params)?;

    // Encrypt with the public key
    let ciphertext = algo.cipher().encrypt_by_name("NACCACHESTERN", pair.public(), &message)?;

    // Decrypt with the private key: the number comes back as a whole block, zeros in front
    let plaintext = algo.cipher().decrypt_by_name("NACCACHESTERN", pair.private(), &ciphertext)?;

    assert!(plaintext.ends_with(&message));
    Ok(())
}
```

### Algorithms

| Name | Aliases | OID | Feature | Padding |
|---|---|---|---|---|
| `NACCACHESTERN` | `NOPADDING`, `RAW` | none | `naccache-stern` | none |

A name may give the mode as `NONE` or `ECB` and the padding by an alias, as
`NACCACHESTERN//NOPADDING` does, and the case of a name does not matter. Bouncy Castle has the
engine but no name for it in `CipherUtilities`.

### Params

The row takes a `NaccacheSternPublicKey` to encrypt and a `NaccacheSternPrivateKey` to decrypt; the
other way round, or any other type, is `InvalidParams`.

### Using it

- **There is no padding**, since a padding would undo the addition of ciphertexts. Equal messages
  give equal ciphertexts, and nothing tells a changed ciphertext from another message: it decrypts
  to another number, or fails to decrypt as `InvalidCiphertext`.
- A message is a number below `σ`, so a few bytes at most; a larger one is `DataLength`.
- Adding ciphertexts is not a row: the engine of `tc_naccache_stern` does it.
- `update` keeps the input, and everything comes out of `finalize`.
