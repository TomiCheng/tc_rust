# ECIES

ECIES is [IES](IES.md) with ECDH for the agreement: each side puts its own private key with the
other's public key, both reach the same shared secret, and the KDF, the MAC and the XOR follow as in
IES.

From two key pairs to the decrypted message. The `ecies` feature of `tc_algo` has the row, and the
derivation value here comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::params::{EcKeyGenParams, IesEcParams};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let message = b"attack at dawn";

    // Both sides have a key pair on the same curve
    let curve = EcKeyGenParams::new("P-256");
    let alice = algo.key_pair_generator().generate_by_name_with("EC", &curve)?;
    let bob = algo.key_pair_generator().generate_by_name_with("EC", &curve)?;
    let (alice_public, alice_private) = alice.into_parts();
    let (bob_public, bob_private) = bob.into_parts();

    // A new derivation value for each message, sent along with it
    let mut derivation = vec![0; 16];
    UnwrapErr(SysRng).fill_bytes(&mut derivation);
    let encoding = b"example protocol v1".to_vec();

    // Alice's private key with Bob's public key encrypts
    let params = IesEcParams::new(
        alice_private,
        bob_public,
        derivation.clone(),
        encoding.clone(),
        128,
    );
    let sealed = algo.cipher().encrypt_by_name("ECIES", &params, message)?;

    // Bob's private key with Alice's public key decrypts
    let params = IesEcParams::new(bob_private, alice_public, derivation, encoding, 128);
    let opened = algo.cipher().decrypt_by_name("ECIES", &params, &sealed)?;

    assert_eq!(opened, message);
    Ok(())
}
```

## Algorithms

| Name | OID | Feature | Agreement | KDF | MAC | Encryption |
|---|---|---|---|---|---|---|
| `ECIES` | none | `ecies` | ECDH | KDF2 over SHA-1 | HMAC-SHA1 | XOR |

The name and parts are those of Bouncy Castle's `CipherUtilities`, and the row gives the vector of
its ECIESTest on secp192r1. The case of the name does not matter. The output is the length of the
message plus 20 bytes of tag.

As in Bouncy Castle, the curve comes from the keys, so the one row takes keys on every curve of the
`EC` key pair generator; see [EC](Ec.md) for the curves.

## Params

The row takes an `IesEcParams`, in `tc_algo::params`, and any other type is `InvalidParams`.

| Argument of `new` | What it is | Secret |
|---|---|---|
| `private_key` | this side's private key from the `EC` generator | yes |
| `public_key` | the other side's public key from it | no |
| `derivation_v` | goes into the KDF, and must differ for each message | no |
| `encoding_v` | goes into the MAC, and is often the context of the protocol | no |
| `mac_key_bits` | the length of `K2`, a whole number of bytes | no |

The keys go in as `KeyPair::into_parts` gives them, `Box<dyn Params>`. Both sides must use the same
curve, `derivation_v`, `encoding_v` and `mac_key_bits`; keys on two curves, or keys that are not EC
keys, are `InvalidParams` from `init`.

## Using it

What [IES](IES.md#using-it) says holds here too:

- **Use a new `derivation_v` for each message.** The keys are static, so the keystream depends
  only on it, and a repeated one repeats the keystream.
- **There are no ephemeral keys**, as in Bouncy Castle C#: the sender needs a key pair of its own,
  and losing a private key exposes every message past and future.
- A changed ciphertext or a wrong key is `InvalidCiphertext`, and the tag is checked before any
  plaintext is formed.
- `update` keeps the input, and everything comes out of `finalize`.
