# EC

An EC key pair is a private number `d` and the point `dG` on an elliptic curve, where `G` is the
curve's generator. ECDH, ECIES, ECMQV and ECDSA all take such keys; the curve is part of each key.

The curves come in four crates, each a feature of `tc_algo` that turns on `ec-key`, the keys, as
well: `fp-custom` has P-256, P-384, P-521, secp256k1, SM2 and the other SEC prime curves of a form of
their own, `fp-curve` Brainpool, GOST, ANSSI and the other prime curves, and `f2m-custom` and
`f2m-curve` the binary ones. The row, and every row over EC keys, is there when one of them is on,
and has the curves of those that are; `fp-custom` alone covers the curves of TLS and X.509.

## Key pairs

From a curve to a new pair:

```rust
use tc_algo::params::generate::EcKeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // P-256, by any of its names, or by its OID with EcKeyGenParams::from_oid
    let params = EcKeyGenParams::new("P-256");

    // Generate the pair
    let pair = algo.key_pair_generator().generate_by_name_with("EC", &params)?;

    // The public key goes to the other side; the private key stays here
    let (_public, _private) = pair.into_parts();
    Ok(())
}
```

### Algorithms

| Name | Aliases | OIDs | Feature | Params | Public key | Private key |
|---|---|---|---|---|---|---|
| `EC` | `ECDH`, `ECIES`, `ECDHC`, `ECMQV`, `ECDSA`, `ECGOST3410`, `ECGOST-3410`, `GOST-3410-2001`, `ECGOST3410-2012`, `GOST-3410-2012` | `1.3.133.16.840.63.0.2`, `.3`, `.16`; `1.3.132.1.11.0` to `.3`; `1.3.132.1.14.0` to `.3`; `1.3.132.1.15.0` to `.3` | `ec-key` | `EcKeyGenParams` | `EcPublicKey<C>` | `EcPrivateKey<C>` |

Bouncy Castle's `GeneratorUtilities` names `EC`, `ECDH` with `ECIES`, `ECDHC`, `ECMQV`, `ECDSA`,
`ECGOST3410` and `ECGOST3410-2012`, each its `ECKeyPairGenerator`; here they are one row, and the case of a name does not matter. The
OIDs are those it gives `EC` and `ECMQV`: dhSinglePass with standard and with cofactor DH, and
mqvSinglePass, each of X9.63 over SHA-1, `1.3.133.16.840.63.0.2`, `.3` and `.16`, and of SEC over
SHA-224 to SHA-512, `1.3.132.1.11.0` to `.3`, `1.3.132.1.14.0` to `.3` and `1.3.132.1.15.0` to `.3`.

### Params

The row takes an `EcKeyGenParams`, in `tc_algo::params`, and any other type is `InvalidParams`:

- `EcKeyGenParams::new(name)` takes a curve name, in any case.
- `EcKeyGenParams::from_oid(oid)` takes its OID.

Neither checks the curve; `init` does, and a curve it does not know is `InvalidParams`.

The names and OIDs are those of Bouncy Castle's `ECNamedCurveTable`, which joins X9.62, SEC, NIST,
TeleTrusT, ANSSI, GOST and GM, and the curves of DSTU 4145, which Bouncy Castle gives by OID alone.
The keys are an `EcPublicKey<C>` and an `EcPrivateKey<C>`, in `tc_algo::params::key`, where `C`
is the type of the curve. [EcKeyGenParams](KeyPairGeneration/EcKeyGenParams.md) lists every
curve, with its names, OID, feature and the alias that names `C`.

### Using it

- `EC` has no curve to assume, since several curves have one size and a guess would pick a wrong
  one quietly, so it needs `init`: `generate_by_name_with`, or `get_by_name`, `init` and
  `generate`. `generate_by_name` gives `NotInitialized`.
- Both sides of an agreement use keys on the same curve.
- Curves below 224 bits, and the binary ones below 233, are too small for new work; they are here
  for old data.
- Each curve is built once, the first time it is used, and its keys borrow it, so they live as
  long as the program.
- The keys draw from the source of `DefaultAlgoBuilder::set_rand`.

## Signing

From a new pair to a verified signature, with ECDSA over SHA-256 on P-256:

```rust
use tc_algo::params::generate::EcKeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "SHA-256withECDSA";
    let message = b"attack at dawn";

    // Generate a pair
    let params = EcKeyGenParams::new("P-256");
    let pair = algo.key_pair_generator().generate_by_name_with("EC", &params)?;

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

The names and OIDs are those of Bouncy Castle's `SignerUtilities`, and the case of a name does not
matter. Each row needs the scheme's feature and the digest's, as `ecdsa` and `sha`.

| Name | Aliases | OIDs | Features |
|---|---|---|---|
| `SHA-1withECDSA` | `ECDSA` | `1.2.840.10045.4.1`, `1.3.36.3.3.2.1` | `ecdsa` and `sha` |
| `SHA-224withECDSA` |  | `1.2.840.10045.4.3.1` | `ecdsa` and `sha` |
| `SHA-256withECDSA` |  | `1.2.840.10045.4.3.2` | `ecdsa` and `sha` |
| `SHA-384withECDSA` |  | `1.2.840.10045.4.3.3` | `ecdsa` and `sha` |
| `SHA-512withECDSA` |  | `1.2.840.10045.4.3.4` | `ecdsa` and `sha` |
| `RIPEMD160withECDSA` |  | `1.3.36.3.3.2.2` | `ecdsa` and `ripemd` |
| `SHA3-224withECDSA` |  | `2.16.840.1.101.3.4.3.9` | `ecdsa` and `keccak` |
| `SHA3-256withECDSA` |  | `2.16.840.1.101.3.4.3.10` | `ecdsa` and `keccak` |
| `SHA3-384withECDSA` |  | `2.16.840.1.101.3.4.3.11` | `ecdsa` and `keccak` |
| `SHA3-512withECDSA` |  | `2.16.840.1.101.3.4.3.12` | `ecdsa` and `keccak` |
| `SHA-1withPLAIN-ECDSA` |  | `0.4.0.127.0.7.1.1.4.1.1` | `ecdsa` and `sha` |
| `SHA-224withPLAIN-ECDSA` |  | `0.4.0.127.0.7.1.1.4.1.2` | `ecdsa` and `sha` |
| `SHA-256withPLAIN-ECDSA` |  | `0.4.0.127.0.7.1.1.4.1.3` | `ecdsa` and `sha` |
| `SHA-384withPLAIN-ECDSA` |  | `0.4.0.127.0.7.1.1.4.1.4` | `ecdsa` and `sha` |
| `SHA-512withPLAIN-ECDSA` |  | `0.4.0.127.0.7.1.1.4.1.5` | `ecdsa` and `sha` |
| `RIPEMD160withPLAIN-ECDSA` |  | `0.4.0.127.0.7.1.1.4.1.6` | `ecdsa` and `ripemd` |
| `SHA3-224withPLAIN-ECDSA` |  | `0.4.0.127.0.7.1.1.4.1.8` | `ecdsa` and `keccak` |
| `SHA3-256withPLAIN-ECDSA` |  | `0.4.0.127.0.7.1.1.4.1.9` | `ecdsa` and `keccak` |
| `SHA3-384withPLAIN-ECDSA` |  | `0.4.0.127.0.7.1.1.4.1.10` | `ecdsa` and `keccak` |
| `SHA3-512withPLAIN-ECDSA` |  | `0.4.0.127.0.7.1.1.4.1.11` | `ecdsa` and `keccak` |
| `SHA-1withCVC-ECDSA` |  | `0.4.0.127.0.7.2.2.2.2.1` | `ecdsa` and `sha` |
| `SHA-224withCVC-ECDSA` |  | `0.4.0.127.0.7.2.2.2.2.2` | `ecdsa` and `sha` |
| `SHA-256withCVC-ECDSA` |  | `0.4.0.127.0.7.2.2.2.2.3` | `ecdsa` and `sha` |
| `SHA-384withCVC-ECDSA` |  | `0.4.0.127.0.7.2.2.2.2.4` | `ecdsa` and `sha` |
| `SHA-512withCVC-ECDSA` |  | `0.4.0.127.0.7.2.2.2.2.5` | `ecdsa` and `sha` |
| `<DIGEST>withECDSA`, for every other digest | `<DIGEST>/ECDSA`, `ECDSAWITH<DIGEST>` |  | `ecdsa` and the digest's |
| `<DIGEST>withPLAIN-ECDSA`, for every other digest | `<DIGEST>/PLAIN-ECDSA`, `PLAIN-ECDSAWITH<DIGEST>` |  | `ecdsa` and the digest's |
| `<DIGEST>withCVC-ECDSA`, for every other digest | `<DIGEST>/CVC-ECDSA`, `CVC-ECDSAWITH<DIGEST>` |  | `ecdsa` and the digest's |
| `<DIGEST>withECNR`, for every digest | `<DIGEST>/ECNR`, `ECNRWITH<DIGEST>` |  | `ecnr` and the digest's |
| `ECGOST3410` | `ECGOST-3410`, `GOST-3410-2001`, `GOST3411WITHECGOST3410`, `GOST3411/ECGOST3410` | `1.2.643.2.2.3` | `ecgost3410` |
| `ECGOST3410-2012-256` | `GOST-3410-2012-256`, `GOST3411-2012-256WITHECGOST3410`, `GOST3411-2012-256/ECGOST3410` and the like | `1.2.643.7.1.1.3.2` | `ecgost3410` |
| `ECGOST3410-2012-512` | `GOST-3410-2012-512`, `GOST3411-2012-512WITHECGOST3410`, `GOST3411-2012-512/ECGOST3410` and the like | `1.2.643.7.1.1.3.3` | `ecgost3410` |

`<DIGEST>` is any name of the digest, so every row is also `SHA256withECDSA`, `SHA-256/ECDSA` and
`ECDSAWITHSHA-256`, after the pattern of the last rows. `NONE`, always there with the scheme, signs
a hash made elsewhere, as `NONEwithECDSA`.

- **ECDSA** gives its signature, r and s, in DER.
- **PLAIN-ECDSA** and **CVC-ECDSA** give r and s side by side, each the size of the curve's order,
  as BSI TR-03111 and the card-verifiable certificates of EAC have it; the two differ in their OIDs
  alone.
- **ECNR** is Nyberg-Rueppel over the curve, in DER.
- **ECGOST3410** is GOST R 34.10-2001 over GOST R 34.11-94, and **ECGOST3410-2012** GOST R
  34.10-2012 over GOST R 34.11-2012 of the same size, on any curve, the GOST curves of
  [EcKeyGenParams](KeyPairGeneration/EcKeyGenParams.md) among them. The digest is the scheme's own, so these rows need no digest feature.

### Params

Every row takes an `EcPrivateKey<C>` to sign and an `EcPublicKey<C>` to verify, on any curve of the
key pair generator above, and any other type is `InvalidParams`.

### Using it

- k is drawn at random for each signature, as Bouncy Castle does, from the source of
  `DefaultAlgoBuilder::set_rand`.
- The rest is common to every signer: [Signers](Signer.md#using-it).

## More

- [ECIES](Ecies.md): encrypting with EC key pairs
