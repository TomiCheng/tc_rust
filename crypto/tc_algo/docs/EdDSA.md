# EdDSA

EdDSA, RFC 8032, signs over the twisted Edwards curves edwards25519 and edwards448. The private key
is 32 or 57 random bytes, and a signature is 64 or 114 bytes. It draws no randomness when it signs:
the same key and message give the same signature.

The `ed25519` feature of `tc_algo` has the rows of Ed25519, and the `ed448` feature those of Ed448.

## Key pairs

A new pair needs no params:

```rust
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    let pair = algo.key_pair_generator().generate_by_name("Ed25519")?;

    let (_public, _private) = pair.into_parts();
    Ok(())
}
```

### Algorithms

| Name | Aliases | OID | Feature | Params | Public key | Private key |
|---|---|---|---|---|---|---|
| `Ed25519` | `Ed25519ctx`, `Ed25519ph` | `1.3.101.112` | `ed25519` | none | `Ed25519PublicKey` | `Ed25519PrivateKey` |
| `Ed448` | `Ed448ph` | `1.3.101.113` | `ed448` | none | `Ed448PublicKey` | `Ed448PrivateKey` |

The names, aliases and OIDs are those of Bouncy Castle's `GeneratorUtilities`, and the case of a
name does not matter.

### Params

None: `generate_by_name` generates a pair, and `init` refuses any params as `InvalidParams`.
`Ed25519PrivateKey::new` and the like make keys of bytes from elsewhere.

## Signing

From a new pair to a verified signature:

```rust
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "Ed25519";
    let message = b"attack at dawn";

    // Generate a pair
    let pair = algo.key_pair_generator().generate_by_name("Ed25519")?;

    // Sign with the private key
    let mut signer = algo.signer().get_by_name(name)?;
    signer.init(pair.private())?;
    signer.update(message)?;
    let signature = signer.sign()?;

    // Verify with the public key
    let mut verifier = algo.signer().get_by_name(name)?;
    verifier.init(pair.public())?;
    verifier.update(message)?;
    assert!(verifier.verify_signature(&signature)?);

    Ok(())
}
```

### Algorithms

| Name | OID | Feature | Signature bytes |
|---|---|---|---|
| `Ed25519` | `1.3.101.112` | `ed25519` | 64 |
| `Ed25519ctx` |  | `ed25519` | 64 |
| `Ed25519ph` |  | `ed25519` | 64 |
| `Ed448` | `1.3.101.113` | `ed448` | 114 |
| `Ed448ph` |  | `ed448` | 114 |

The names and OIDs are those of Bouncy Castle's `SignerUtilities`, and the case of a name does not
matter. `ph` signs the SHA-512 or SHAKE256 hash of the message, and `ctx` and `ph` take a context,
which is empty here, as Bouncy Castle builds them.

### Params

Each row takes the private key of its curve to sign and the public key to verify, and any other
type, the other curve's among them, is `InvalidParams`.

### Using it

- The rest is common to every signer: [Signers](Signer.md#using-it).
