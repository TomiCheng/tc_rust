# Key agreements

`tc_algo::agreement` creates key agreements by name or by OID, after Bouncy Castle's
`AgreementUtilities`. Two parties each make a key pair with `generate::key_pair`,
swap public keys, and each combines its own private key with the other's public key
for the same secret.

Each agreement has a guide of its own, which is all you need to use it:

- [DH](agreement/dh.md): finite-field Diffie-Hellman, in a group both parties share.
- [X25519](agreement/x25519.md): Diffie-Hellman on Curve25519, of RFC 7748.

## Enabling agreements

Each agreement comes with the feature of its algorithm, listed in the
[table](#algorithms) below, which also enables its keys and their generator. Both
are in the default features.

```toml
[dependencies]
# Keep only what you use
tc_algo = { version = "0.1", default-features = false, features = ["x25519"] }
```

## Usage

Every agreement takes the same steps; only the name and, for DH, the group differ.

```rust
use tc_algo::AlgoError;
use tc_algo::agreement;
use tc_algo::generate;

fn main() -> Result<(), AlgoError> {
    let alice = generate::key_pair::generate("X25519")?;
    let bob = generate::key_pair::generate("X25519")?;

    let mut agreement = agreement::get_by_name("X25519")?;
    agreement.init(&alice.private.into())?;
    let secret = agreement.calculate(&bob.public.into())?;
    Ok(())
}
```

`init` takes this party's private key in an `AnyAgreementParams` and `calculate` the
other party's public key in an `AgreementPeer`; `.into()` makes either from the key
alone. `agreement::calculate` does all three steps at once.

The result is a `SharedSecret`, the raw secret of the agreement. It is not yet a key:
derive the key from it with a KDF. Its bytes are wiped when it is dropped.

### By name or OID

Names match without regard to ASCII case, and a dotted OID string works wherever a
name does. `agreement::get_by_oid` takes an `Asn1Oid`.

```rust
use tc_algo::agreement;
use tc_algo::{AlgoError, ErrorKind};

fn main() -> Result<(), AlgoError> {
    let x25519 = agreement::get_by_name("1.3.101.110")?;
    assert_eq!(x25519.entry().name(), "X25519");

    let error = agreement::get_by_name("no-such-agreement").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownAgreement);
    Ok(())
}
```

### Looking at the table

```rust
use tc_algo::agreement;

for entry in agreement::algorithms() {
    println!("{entry}"); // e.g. `X25519  [id-X25519]`
}
```

## Algorithms

| Name | Aliases | OID | Secret | Feature | Default |
|---|---|---|---:|---|:---:|
| DH | DIFFIEHELLMAN | | bytes of p | `dh` | ✓ |
| X25519 | | 1.3.101.110 | 32 bytes | `x25519` | ✓ |

The generator of each has the same name and OID; see [generator.md](generator.md).
