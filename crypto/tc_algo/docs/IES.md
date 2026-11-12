# IES

The Integrated Encryption Scheme encrypts a message of any length to someone's public key, and
authenticates it. It joins parts that are otherwise separate rows:

```text
own private key + other's public key -> agreement -> shared secret Z
Z + derivation value -> KDF -> MAC key K2 + keystream K1
message XOR K1 -> ciphertext C
MAC(K2, C + encoding value) -> tag T

output: C + T
```

The other side uses its own private key and the sender's public key, reaches the same `Z`, checks
`T`, and only then decrypts.

From two key pairs to the decrypted message. The `ies` feature of `tc_algo` has the row, and the
derivation value here comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::generate::KeyPair;
use tc_algo::params::dh_groups::rfc3526_2048;
use tc_algo::params::{DhPrivateKey, DhPublicKey, IesDhParams};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn private(pair: &KeyPair) -> DhPrivateKey {
    let key = pair.private().as_any().downcast_ref::<DhPrivateKey>();
    key.expect("a DH key").clone()
}

fn public(pair: &KeyPair) -> DhPublicKey {
    let key = pair.public().as_any().downcast_ref::<DhPublicKey>();
    key.expect("a DH key").clone()
}

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let message = b"attack at dawn";

    // Both sides have a key pair of the same group
    let group = rfc3526_2048();
    let alice = algo.key_pair_generator().generate_by_name_with("DH", &group)?;
    let bob = algo.key_pair_generator().generate_by_name_with("DH", &group)?;

    // A new derivation value for each message, sent along with it
    let mut derivation = vec![0; 16];
    UnwrapErr(SysRng).fill_bytes(&mut derivation);
    let encoding = b"example protocol v1".to_vec();

    // Alice's private key with Bob's public key encrypts
    let params = IesDhParams::new(
        private(&alice),
        public(&bob),
        derivation.clone(),
        encoding.clone(),
        128,
    );
    let sealed = algo.cipher().encrypt_by_name("IES", &params, message)?;

    // Bob's private key with Alice's public key decrypts
    let params = IesDhParams::new(private(&bob), public(&alice), derivation, encoding, 128);
    let opened = algo.cipher().decrypt_by_name("IES", &params, &sealed)?;

    assert_eq!(opened, message);
    Ok(())
}
```

## Algorithms

| Name | OID | Feature | Agreement | KDF | MAC | Encryption |
|---|---|---|---|---|---|---|
| `IES` | none | `ies` | DH | KDF2 over SHA-1 | HMAC-SHA1 | XOR |

The case of the name does not matter. The output is the length of the message plus 20 bytes of tag.

Bouncy Castle's `CipherUtilities` also has `ECIES`: the same parts, with ECDH for the agreement.
It is not a row yet, since `tc_algo` has no EC keys to give it.

The name and parts are those of Bouncy Castle's `CipherUtilities`, but there is no behaviour of its
to compare with: the `Init` of its `BufferedIesCipher` throws `NotImplementedException`. This row
follows that class, and gives the same output as `IesEngine` of `tc_ies` over the same parts.

## Params

The row takes an `IesDhParams`, in `tc_algo::params`, and any other type is `InvalidParams`.

| Argument of `new` | What it is | Secret |
|---|---|---|
| `private_key` | this side's `DhPrivateKey` | yes |
| `public_key` | the other side's `DhPublicKey` | no |
| `derivation_v` | goes into the KDF, and must differ for each message | no |
| `encoding_v` | goes into the MAC, and is often the context of the protocol | no |
| `mac_key_bits` | the length of `K2`, a whole number of bytes | no |

Both sides must use the same `derivation_v`, `encoding_v` and `mac_key_bits`. The keys must be of the
same group, or `init` gives `InvalidParams`.

## Using it

- **Use a new `derivation_v` for each message.** Both keys are static, so `Z` never changes, and the
  keystream depends only on `Z` and `derivation_v`. If the value repeats, so does the keystream, and
  the XOR of two ciphertexts is the XOR of their messages. Nothing checks this. Reversing the
  direction does not help either: both directions reach the same `Z`.
- **There are no ephemeral keys.** The usual ECIES makes a new key pair for each message and sends
  the public key. This scheme, as in Bouncy Castle C#, does not, so the sender needs a key pair, and
  losing a private key exposes every message past and future.
- **SHA-1 is what Bouncy Castle fixes here.** HMAC and KDF2 do not rest on the collision resistance
  that SHA-1 has lost, but prefer something else for new work.
- A changed ciphertext or a wrong key is `InvalidCiphertext`, as is an input shorter than the tag. The
  tag is checked before any plaintext is formed.
- `update` keeps the input, and everything comes out of `finalize`, which starts the next message
  under the same keys. `reset` discards the message so far.
- `update` and `finalize` give `NotInitialized` before an `init` that succeeded.
