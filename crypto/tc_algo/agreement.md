# Key agreements

`algo.agreement()` creates key agreements by name or by OID, after Bouncy Castle's
`AgreementUtilities`. Two parties each make a key pair with `algo.key_pair_generator()`,
swap public keys, and each combines its own private key with the other's public key
for the same secret.

Each agreement has a guide of its own, which is all you need to use it:

- [DH](agreement/dh.md): finite-field Diffie-Hellman, in a group both parties share.
- [ECDH](agreement/ecdh.md): ECDH and ECDHC, Diffie-Hellman on a named elliptic curve
  both parties share.
- [ECMQV](agreement/ecmqv.md): MQV on a named elliptic curve, with a static and an
  ephemeral key of each party.
- [X25519](agreement/x25519.md): Diffie-Hellman on Curve25519, of RFC 7748.
- [X448](agreement/x448.md): Diffie-Hellman on Curve448, of RFC 7748.
- [GOST VKO](agreement/ecvko.md): ECGOST3410 and its 2012 versions, on the GOST
  curves with a UKM both parties know.

## Enabling agreements

Nothing is on by default. Each agreement comes with the feature of its algorithm, listed in
the [table](#algorithms) below, which also enables its keys and their generator.

```toml
[dependencies]
tc_algo = { version = "0.1", features = ["x25519"] }
```

## Usage

Every agreement takes the same steps; only the name and, for DH and the EC
agreements, the group or the curve differ. ECMQV also takes an ephemeral key of each
party, and GOST VKO a UKM.

```rust
use tc_algo::{Algo, AlgoError};

fn main() -> Result<(), AlgoError> {
    let algo = Algo::new();
    let alice = algo.key_pair_generator().generate("X25519")?;
    let bob = algo.key_pair_generator().generate("X25519")?;

    let mut agreement = algo.agreement().get_by_name("X25519")?;
    agreement.init(&alice.private.into())?;
    let secret = agreement.calculate(&bob.public.into())?;
    Ok(())
}
```

`init` takes this party's private key in an `AnyAgreementParams` and `calculate` the
other party's public key in an `AgreementPeer`; `.into()` makes either from the key
alone, their `with_ephemeral` adds the ephemeral key ECMQV takes, and the params'
`with_ukm` the UKM VKO takes. `algo.agreement().calculate` does all three steps at once.

The result is a `SharedSecret`, the raw secret of the agreement. It is not yet a key:
derive the key from it with a KDF. Its bytes are wiped when it is dropped.

### By name or OID

Names match without regard to ASCII case, and a dotted OID string works wherever a
name does. `algo.agreement().get_by_oid` takes an `Asn1Oid`.

```rust
use tc_algo::{Algo, AlgoError, ErrorKind};

fn main() -> Result<(), AlgoError> {
    let algo = Algo::new();
    let x25519 = algo.agreement().get_by_name("1.3.101.110")?;
    assert_eq!(x25519.entry().name(), "X25519");

    let error = algo.agreement().get_by_name("no-such-agreement").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownAgreement);
    Ok(())
}
```

### Looking at the table

```rust
use tc_algo::Algo;

let algo = Algo::new();
for entry in algo.agreement().algorithms() {
    println!("{entry}"); // e.g. `X25519  [id-X25519]`
}
```

## Algorithms

| Name | Aliases | OID | Secret | Feature |
|---|---|---|---:|---|
| DH | DIFFIEHELLMAN | | bytes of p | `dh` |
| ECDH | | | bytes of a coordinate | `ecdh` |
| ECDHC | ECCDH | | bytes of a coordinate | `ecdh` |
| ECMQV | | | bytes of a coordinate | `ecmqv` |
| X25519 | | 1.3.101.110 | 32 bytes | `x25519` |
| X448 | | 1.3.101.111 | 56 bytes | `x448` |
| ECGOST3410-2012-256 | | 1.2.643.7.1.1.6.1, 1.2.643.7.1.1.1.1 | 32 bytes | `ecvko` |
| ECGOST3410-2012-512 | | 1.2.643.7.1.1.6.2, 1.2.643.7.1.1.1.2 | 64 bytes | `ecvko` |
| ECGOST3410 | GOST-3410-2001 | 1.2.643.2.2.19, 1.2.643.2.2.96 | 32 bytes | `ecvko`, `gost3411` |

Each name but the VKO ones finds the generator of its keys as well, EC for ECDH, ECDHC
and ECMQV; the VKO keys come from EC on a GOST curve. See [generator.md](generator.md).
