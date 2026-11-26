# DSA

DSA, FIPS 186, signs with a private number `x` and verifies with `y = g^x mod p`, over a domain of
primes `p` and `q` and a generator `g` that both sides share. Each signature draws a new random `k`.

The `dsa` feature of `tc_algo` has the rows. FIPS 186-5 no longer approves DSA for new signatures; it
is here for old data and for keys that are already in use.

## Key pairs

A new domain and a pair over it:

```rust
use tc_algo::params::generate::DsaKeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A new domain of p of 2048 bits and q of 256, then a pair over it
    let params = DsaKeyGenParams::new(2048, 256);
    let pair = algo.key_pair_generator().generate_by_name_with("DSA", &params)?;

    let (_public, _private) = pair.into_parts();
    Ok(())
}
```

### Algorithms

| Name | OID | Feature | Params | Public key | Private key |
|---|---|---|---|---|---|
| `DSA` |  | `dsa` | `DsaKeyGenParams`, `DsaParameters` | `DsaPublicKey` | `DsaPrivateKey` |

The name is that of Bouncy Castle's `GeneratorUtilities`, and its case does not matter.

### Params

- `DsaKeyGenParams::new(l, n)` generates a new domain at `init`, over SHA-256 as FIPS 186-3 has it:
  p of `l` bits and q of `n`, where (l, n) is (1024, 160), (2048, 224), (2048, 256) or (3072, 256).
  Generating a domain takes a while, so `init` once and `generate` as many pairs as needed.
- A `DsaParameters`, the domain of another key as `DsaPublicKey::params` gives it, or one from
  elsewhere, makes more pairs over the same domain.

Any other type is `InvalidParams`, and so is a domain that tc_dsa_signer refuses.
[DsaKeyGenParams](KeyPairGeneration/DsaKeyGenParams.md) lists the settings and the checks.

## Signing

From a new pair to a verified signature, with DSA over SHA-256:

```rust
use tc_algo::params::generate::DsaKeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "SHA-256withDSA";
    let message = b"attack at dawn";

    // Generate a pair
    let params = DsaKeyGenParams::new(2048, 256);
    let pair = algo.key_pair_generator().generate_by_name_with("DSA", &params)?;

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
matter. Each row needs `dsa` and the digest's feature.

| Name | Aliases | OIDs | Features |
|---|---|---|---|
| `SHA-1withDSA` | `DSA` | `1.2.840.10040.4.3`, `1.3.14.3.2.27` | `dsa` and `sha` |
| `SHA-224withDSA` |  | `2.16.840.1.101.3.4.3.1` | `dsa` and `sha` |
| `SHA-256withDSA` |  | `2.16.840.1.101.3.4.3.2` | `dsa` and `sha` |
| `SHA-384withDSA` |  | `2.16.840.1.101.3.4.3.3` | `dsa` and `sha` |
| `SHA-512withDSA` |  | `2.16.840.1.101.3.4.3.4` | `dsa` and `sha` |
| `SHA3-224withDSA` |  | `2.16.840.1.101.3.4.3.5` | `dsa` and `keccak` |
| `SHA3-256withDSA` |  | `2.16.840.1.101.3.4.3.6` | `dsa` and `keccak` |
| `SHA3-384withDSA` |  | `2.16.840.1.101.3.4.3.7` | `dsa` and `keccak` |
| `SHA3-512withDSA` |  | `2.16.840.1.101.3.4.3.8` | `dsa` and `keccak` |
| `<DIGEST>withDSA`, for every other digest | `<DIGEST>/DSA`, `DSAWITH<DIGEST>` |  | `dsa` and the digest's |

`<DIGEST>` is any name of the digest, so every row is also `SHA256withDSA`, `SHA-256/DSA` and
`DSAWITHSHA-256`. `NONEwithDSA`, also `RAWDSA`, always there with the row, signs a hash made
elsewhere. The signature is r and s in DER.

### Params

Every row takes a `DsaPrivateKey` to sign and a `DsaPublicKey` to verify, and any other type is
`InvalidParams`.

### Using it

- k is drawn at random for each signature, as Bouncy Castle does, from the source of
  `DefaultAlgoBuilder::set_rand`.
- The rest is common to every signer: [Signers](Signer.md#using-it).
