# EC

An EC key pair is a private number `d` and the point `dG` on an elliptic curve, where `G` is the
curve's generator. ECDH, ECIES, ECMQV and ECDSA all take such keys; the curve is part of each key.

The `ec` feature of `tc_algo` has the row.

## Key pairs

From a curve to a new pair:

```rust
use tc_algo::params::EcKeyGenParams;
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
| `EC` | `ECDH`, `ECIES`, `ECDHC`, `ECMQV`, `ECDSA` | X9.63 and SEC schemes, below | `ec` | `EcKeyGenParams` | `EcPublicKey<C>` | `EcPrivateKey<C>` |

Bouncy Castle's `GeneratorUtilities` names `EC`, `ECDH` with `ECIES`, `ECDHC`, `ECMQV` and `ECDSA`,
each its `ECKeyPairGenerator`; here they are one row, and the case of a name does not matter. The
OIDs are those it gives `EC` and `ECMQV`: dhSinglePass with standard and with cofactor DH, and
mqvSinglePass, each of X9.63 over SHA-1, `1.3.133.16.840.63.0.2`, `.3` and `.16`, and of SEC over
SHA-224 to SHA-512, `1.3.132.1.11.0` to `.3`, `1.3.132.1.14.0` to `.3` and `1.3.132.1.15.0` to `.3`.

### Params

The row takes an `EcKeyGenParams`, in `tc_algo::params`, and any other type is `InvalidParams`:

- `EcKeyGenParams::new(name)` takes a name of the table below, in any case.
- `EcKeyGenParams::from_oid(oid)` takes its OID.

Neither checks the curve; `init` does, and a curve the table does not have is `InvalidParams`.

The names and OIDs are those of Bouncy Castle's `ECNamedCurveTable`, which joins X9.62, SEC, NIST,
TeleTrusT, ANSSI, GOST and GM, and the curves of DSTU 4145, which Bouncy Castle gives by OID alone.
The keys are an `EcPublicKey<C>` and an `EcPrivateKey<C>` of `tc_ec_key`, where `C` is the type
of the curve, as the table gives it for each: a curve with a special form of its own runs on the
faster arithmetic of `tc_fp_custom` or `tc_f2m_custom`, the others on the generic one of
`tc_fp_curve` or `tc_f2m_curve`, all in constant time. `as_any().downcast_ref::<EcPublicKey<C>>()`
gives a key back with that `C`.

| Names | OID | Field | Curve type `C` |
|---|---|---|---|
| `secp112r1` | `1.3.132.0.6` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `secp112r2` | `1.3.132.0.7` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `secp128r1` | `1.3.132.0.28` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP128R1FieldElement>` |
| `secp128r2` | `1.3.132.0.29` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `secp160k1` | `1.3.132.0.9` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP160R2FieldElement>` |
| `secp160r1` | `1.3.132.0.8` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP160R1FieldElement>` |
| `secp160r2` | `1.3.132.0.30` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP160R2FieldElement>` |
| `secp192k1` | `1.3.132.0.31` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP192K1FieldElement>` |
| `secp192r1`, `prime192v1`, `P-192` | `1.2.840.10045.3.1.1` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP192R1FieldElement>` |
| `secp224k1` | `1.3.132.0.32` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP224K1FieldElement>` |
| `secp224r1`, `P-224` | `1.3.132.0.33` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP224R1FieldElement>` |
| `secp256k1` | `1.3.132.0.10` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP256K1FieldElement>` |
| `secp256r1`, `prime256v1`, `P-256` | `1.2.840.10045.3.1.7` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP256R1FieldElement>` |
| `secp384r1`, `P-384` | `1.3.132.0.34` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP384R1FieldElement>` |
| `secp521r1`, `P-521` | `1.3.132.0.35` | prime | `&'static tc_fp_custom::SecPCtCurve<SecP521R1FieldElement>` |
| `sect113r1` | `1.3.132.0.4` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT113FieldElement>` |
| `sect113r2` | `1.3.132.0.5` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT113FieldElement>` |
| `sect131r1` | `1.3.132.0.22` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT131FieldElement>` |
| `sect131r2` | `1.3.132.0.23` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT131FieldElement>` |
| `sect163k1`, `K-163` | `1.3.132.0.1` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT163FieldElement>` |
| `sect163r1` | `1.3.132.0.2` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT163FieldElement>` |
| `sect163r2`, `B-163` | `1.3.132.0.15` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT163FieldElement>` |
| `sect193r1` | `1.3.132.0.24` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT193FieldElement>` |
| `sect193r2` | `1.3.132.0.25` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT193FieldElement>` |
| `sect233k1`, `K-233` | `1.3.132.0.26` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT233FieldElement>` |
| `sect233r1`, `B-233` | `1.3.132.0.27` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT233FieldElement>` |
| `sect239k1` | `1.3.132.0.3` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT239FieldElement>` |
| `sect283k1`, `K-283` | `1.3.132.0.16` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT283FieldElement>` |
| `sect283r1`, `B-283` | `1.3.132.0.17` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT283FieldElement>` |
| `sect409k1`, `K-409` | `1.3.132.0.36` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT409FieldElement>` |
| `sect409r1`, `B-409` | `1.3.132.0.37` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT409FieldElement>` |
| `sect571k1`, `K-571` | `1.3.132.0.38` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT571FieldElement>` |
| `sect571r1`, `B-571` | `1.3.132.0.39` | binary | `&'static tc_f2m_custom::SecTCtCurve<SecT571FieldElement>` |
| `prime192v2` | `1.2.840.10045.3.1.2` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `prime192v3` | `1.2.840.10045.3.1.3` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `prime239v1` | `1.2.840.10045.3.1.4` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `prime239v2` | `1.2.840.10045.3.1.5` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `prime239v3` | `1.2.840.10045.3.1.6` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `c2pnb163v1` | `1.2.840.10045.3.0.1` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2pnb163v2` | `1.2.840.10045.3.0.2` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2pnb163v3` | `1.2.840.10045.3.0.3` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2pnb176w1` | `1.2.840.10045.3.0.4` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2tnb191v1` | `1.2.840.10045.3.0.5` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2tnb191v2` | `1.2.840.10045.3.0.6` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2tnb191v3` | `1.2.840.10045.3.0.7` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2pnb208w1` | `1.2.840.10045.3.0.10` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2tnb239v1` | `1.2.840.10045.3.0.11` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2tnb239v2` | `1.2.840.10045.3.0.12` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2tnb239v3` | `1.2.840.10045.3.0.13` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2pnb272w1` | `1.2.840.10045.3.0.16` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2pnb304w1` | `1.2.840.10045.3.0.17` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2tnb359v1` | `1.2.840.10045.3.0.18` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2pnb368w1` | `1.2.840.10045.3.0.19` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `c2tnb431r1` | `1.2.840.10045.3.0.20` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| `brainpoolP160r1` | `1.3.36.3.3.2.8.1.1.1` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP160t1` | `1.3.36.3.3.2.8.1.1.2` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP192r1` | `1.3.36.3.3.2.8.1.1.3` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP192t1` | `1.3.36.3.3.2.8.1.1.4` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP224r1` | `1.3.36.3.3.2.8.1.1.5` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP224t1` | `1.3.36.3.3.2.8.1.1.6` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP256r1` | `1.3.36.3.3.2.8.1.1.7` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP256t1` | `1.3.36.3.3.2.8.1.1.8` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP320r1` | `1.3.36.3.3.2.8.1.1.9` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP320t1` | `1.3.36.3.3.2.8.1.1.10` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP384r1` | `1.3.36.3.3.2.8.1.1.11` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP384t1` | `1.3.36.3.3.2.8.1.1.12` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP512r1` | `1.3.36.3.3.2.8.1.1.13` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `brainpoolP512t1` | `1.3.36.3.3.2.8.1.1.14` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `FRP256v1` | `1.2.250.1.223.101.256.1` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `GostR3410-2001-CryptoPro-A` | `1.2.643.2.2.35.1` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `GostR3410-2001-CryptoPro-B` | `1.2.643.2.2.35.2` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `GostR3410-2001-CryptoPro-C` | `1.2.643.2.2.35.3` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `GostR3410-2001-CryptoPro-XchA` | `1.2.643.2.2.36.0` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `GostR3410-2001-CryptoPro-XchB` | `1.2.643.2.2.36.1` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `Tc26-Gost-3410-12-256-paramSetA` | `1.2.643.7.1.2.1.1.1` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `Tc26-Gost-3410-12-256-paramSetB` | `1.2.643.7.1.2.1.1.2` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `Tc26-Gost-3410-12-256-paramSetC` | `1.2.643.7.1.2.1.1.3` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `Tc26-Gost-3410-12-256-paramSetD` | `1.2.643.7.1.2.1.1.4` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `Tc26-Gost-3410-12-512-paramSetA` | `1.2.643.7.1.2.1.2.1` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `Tc26-Gost-3410-12-512-paramSetB` | `1.2.643.7.1.2.1.2.2` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `Tc26-Gost-3410-12-512-paramSetC` | `1.2.643.7.1.2.1.2.3` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `wapip192v1` | `1.2.156.10197.1.301.101` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `wapi192v1` | `1.2.156.11235.1.1.1` | prime | `&'static tc_fp_curve::FpCtCurve<'static>` |
| `sm2p256v1` | `1.2.156.10197.1.301` | prime | `&'static tc_fp_custom::SecPCtCurve<SM2P256V1FieldElement>` |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.0` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.1` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.2` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.3` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.4` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.5` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.6` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.7` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.8` | binary | `&'static tc_f2m_curve::F2mCtCurve` |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.9` | binary | `&'static tc_f2m_curve::F2mCtCurve` |

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

## More

- [ECIES](Ecies.md): encrypting with EC key pairs
