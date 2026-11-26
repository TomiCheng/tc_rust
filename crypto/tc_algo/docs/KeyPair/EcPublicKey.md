# EcPublicKey and EcPrivateKey

Enable `fp-custom`, `fp-curve`, `f2m-custom` or `f2m-curve`, the feature of the curve. Import the
keys from `tc_algo::params::key`. The `EC` key pair generator returns an `EcPublicKey<C>` and an
`EcPrivateKey<C>`, where `C` is the type of the curve. Each named curve has aliases for `C` and
its keys, such as `Secp256r1`, `EcSecp256r1PublicKey` and `EcSecp256r1PrivateKey`;
[EcKeyGenParams](../KeyPairGeneration/EcKeyGenParams.md#curves) lists them with their features.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `g` | The base point, which carries the curve and its order | yes | yes | `g()` |
| `q` | The public point | yes | | `q()` |
| `d` | The private scalar | | yes | `d()` |

`g` and `q` are `&C::Point`, and `d` a `&PaddedBigUint`. A key is built from the same fields:

| Build | Gives |
|---|---|
| `EcPublicKey::new(g, &q)` | The public key, or `InvalidPublicPoint` |
| `EcPrivateKey::new(g, d)` | The private key, or `MissingOrder` or `InvalidPrivateScalar` |

The points and the scalar read from another key, as the example does, need no import.
`EcPublicKey::new` moves `q` onto the curve of `g` and turns it down when it is infinity or not a
point of the subgroup. `EcPrivateKey::new` needs the order of the curve and checks that `d` is in
`[1, n - 1]`. Both keys are `Clone`, with no `Debug` or `PartialEq`, and the private key wipes `d`
when it is dropped.

## Key types

The aliases in `tc_algo::params::key` for each named curve: the curve type `C` and the two key types
over it. Curves of the generic `tc_fp_curve` or `tc_f2m_curve` share one type, and some curves of
`tc_fp_custom` and `tc_f2m_custom` share theirs, so a downcast does not tell those curves apart;
[EcKeyGenParams](../KeyPairGeneration/EcKeyGenParams.md#curves) has their other names and OIDs.

| Curve | Curve type `C` | Public key | Private key | Feature | Note |
|---|---|---|---|---|---|
| `secp112r1` | `Secp112r1` | `EcSecp112r1PublicKey` | `EcSecp112r1PrivateKey` | `fp-curve` | weak |
| `secp112r2` | `Secp112r2` | `EcSecp112r2PublicKey` | `EcSecp112r2PrivateKey` | `fp-curve` | weak |
| `secp128r1` | `Secp128r1` | `EcSecp128r1PublicKey` | `EcSecp128r1PrivateKey` | `fp-custom` | weak |
| `secp128r2` | `Secp128r2` | `EcSecp128r2PublicKey` | `EcSecp128r2PrivateKey` | `fp-curve` | weak |
| `secp160k1` | `Secp160k1` | `EcSecp160k1PublicKey` | `EcSecp160k1PrivateKey` | `fp-custom` | weak |
| `secp160r1` | `Secp160r1` | `EcSecp160r1PublicKey` | `EcSecp160r1PrivateKey` | `fp-custom` | weak |
| `secp160r2` | `Secp160r2` | `EcSecp160r2PublicKey` | `EcSecp160r2PrivateKey` | `fp-custom` | weak |
| `secp192k1` | `Secp192k1` | `EcSecp192k1PublicKey` | `EcSecp192k1PrivateKey` | `fp-custom` | weak |
| `secp192r1` | `Secp192r1` | `EcSecp192r1PublicKey` | `EcSecp192r1PrivateKey` | `fp-custom` | weak |
| `secp224k1` | `Secp224k1` | `EcSecp224k1PublicKey` | `EcSecp224k1PrivateKey` | `fp-custom` |  |
| `secp224r1` | `Secp224r1` | `EcSecp224r1PublicKey` | `EcSecp224r1PrivateKey` | `fp-custom` |  |
| `secp256k1` | `Secp256k1` | `EcSecp256k1PublicKey` | `EcSecp256k1PrivateKey` | `fp-custom` |  |
| `secp256r1` | `Secp256r1` | `EcSecp256r1PublicKey` | `EcSecp256r1PrivateKey` | `fp-custom` |  |
| `secp384r1` | `Secp384r1` | `EcSecp384r1PublicKey` | `EcSecp384r1PrivateKey` | `fp-custom` |  |
| `secp521r1` | `Secp521r1` | `EcSecp521r1PublicKey` | `EcSecp521r1PrivateKey` | `fp-custom` |  |
| `sect113r1` | `Sect113r1` | `EcSect113r1PublicKey` | `EcSect113r1PrivateKey` | `f2m-custom` | weak |
| `sect113r2` | `Sect113r2` | `EcSect113r2PublicKey` | `EcSect113r2PrivateKey` | `f2m-custom` | weak |
| `sect131r1` | `Sect131r1` | `EcSect131r1PublicKey` | `EcSect131r1PrivateKey` | `f2m-custom` | weak |
| `sect131r2` | `Sect131r2` | `EcSect131r2PublicKey` | `EcSect131r2PrivateKey` | `f2m-custom` | weak |
| `sect163k1` | `Sect163k1` | `EcSect163k1PublicKey` | `EcSect163k1PrivateKey` | `f2m-custom` | weak |
| `sect163r1` | `Sect163r1` | `EcSect163r1PublicKey` | `EcSect163r1PrivateKey` | `f2m-custom` | weak |
| `sect163r2` | `Sect163r2` | `EcSect163r2PublicKey` | `EcSect163r2PrivateKey` | `f2m-custom` | weak |
| `sect193r1` | `Sect193r1` | `EcSect193r1PublicKey` | `EcSect193r1PrivateKey` | `f2m-custom` | weak |
| `sect193r2` | `Sect193r2` | `EcSect193r2PublicKey` | `EcSect193r2PrivateKey` | `f2m-custom` | weak |
| `sect233k1` | `Sect233k1` | `EcSect233k1PublicKey` | `EcSect233k1PrivateKey` | `f2m-custom` |  |
| `sect233r1` | `Sect233r1` | `EcSect233r1PublicKey` | `EcSect233r1PrivateKey` | `f2m-custom` |  |
| `sect239k1` | `Sect239k1` | `EcSect239k1PublicKey` | `EcSect239k1PrivateKey` | `f2m-custom` |  |
| `sect283k1` | `Sect283k1` | `EcSect283k1PublicKey` | `EcSect283k1PrivateKey` | `f2m-custom` |  |
| `sect283r1` | `Sect283r1` | `EcSect283r1PublicKey` | `EcSect283r1PrivateKey` | `f2m-custom` |  |
| `sect409k1` | `Sect409k1` | `EcSect409k1PublicKey` | `EcSect409k1PrivateKey` | `f2m-custom` |  |
| `sect409r1` | `Sect409r1` | `EcSect409r1PublicKey` | `EcSect409r1PrivateKey` | `f2m-custom` |  |
| `sect571k1` | `Sect571k1` | `EcSect571k1PublicKey` | `EcSect571k1PrivateKey` | `f2m-custom` |  |
| `sect571r1` | `Sect571r1` | `EcSect571r1PublicKey` | `EcSect571r1PrivateKey` | `f2m-custom` |  |
| `prime192v2` | `Prime192v2` | `EcPrime192v2PublicKey` | `EcPrime192v2PrivateKey` | `fp-curve` | weak |
| `prime192v3` | `Prime192v3` | `EcPrime192v3PublicKey` | `EcPrime192v3PrivateKey` | `fp-curve` | weak |
| `prime239v1` | `Prime239v1` | `EcPrime239v1PublicKey` | `EcPrime239v1PrivateKey` | `fp-curve` |  |
| `prime239v2` | `Prime239v2` | `EcPrime239v2PublicKey` | `EcPrime239v2PrivateKey` | `fp-curve` |  |
| `prime239v3` | `Prime239v3` | `EcPrime239v3PublicKey` | `EcPrime239v3PrivateKey` | `fp-curve` |  |
| `c2pnb163v1` | `C2pnb163v1` | `EcC2pnb163v1PublicKey` | `EcC2pnb163v1PrivateKey` | `f2m-curve` | weak |
| `c2pnb163v2` | `C2pnb163v2` | `EcC2pnb163v2PublicKey` | `EcC2pnb163v2PrivateKey` | `f2m-curve` | weak |
| `c2pnb163v3` | `C2pnb163v3` | `EcC2pnb163v3PublicKey` | `EcC2pnb163v3PrivateKey` | `f2m-curve` | weak |
| `c2pnb176w1` | `C2pnb176w1` | `EcC2pnb176w1PublicKey` | `EcC2pnb176w1PrivateKey` | `f2m-curve` | weak |
| `c2tnb191v1` | `C2tnb191v1` | `EcC2tnb191v1PublicKey` | `EcC2tnb191v1PrivateKey` | `f2m-curve` | weak |
| `c2tnb191v2` | `C2tnb191v2` | `EcC2tnb191v2PublicKey` | `EcC2tnb191v2PrivateKey` | `f2m-curve` | weak |
| `c2tnb191v3` | `C2tnb191v3` | `EcC2tnb191v3PublicKey` | `EcC2tnb191v3PrivateKey` | `f2m-curve` | weak |
| `c2pnb208w1` | `C2pnb208w1` | `EcC2pnb208w1PublicKey` | `EcC2pnb208w1PrivateKey` | `f2m-curve` | weak |
| `c2tnb239v1` | `C2tnb239v1` | `EcC2tnb239v1PublicKey` | `EcC2tnb239v1PrivateKey` | `f2m-curve` |  |
| `c2tnb239v2` | `C2tnb239v2` | `EcC2tnb239v2PublicKey` | `EcC2tnb239v2PrivateKey` | `f2m-curve` |  |
| `c2tnb239v3` | `C2tnb239v3` | `EcC2tnb239v3PublicKey` | `EcC2tnb239v3PrivateKey` | `f2m-curve` |  |
| `c2pnb272w1` | `C2pnb272w1` | `EcC2pnb272w1PublicKey` | `EcC2pnb272w1PrivateKey` | `f2m-curve` |  |
| `c2pnb304w1` | `C2pnb304w1` | `EcC2pnb304w1PublicKey` | `EcC2pnb304w1PrivateKey` | `f2m-curve` |  |
| `c2tnb359v1` | `C2tnb359v1` | `EcC2tnb359v1PublicKey` | `EcC2tnb359v1PrivateKey` | `f2m-curve` |  |
| `c2pnb368w1` | `C2pnb368w1` | `EcC2pnb368w1PublicKey` | `EcC2pnb368w1PrivateKey` | `f2m-curve` |  |
| `c2tnb431r1` | `C2tnb431r1` | `EcC2tnb431r1PublicKey` | `EcC2tnb431r1PrivateKey` | `f2m-curve` |  |
| `brainpoolP160r1` | `BrainpoolP160r1` | `EcBrainpoolP160r1PublicKey` | `EcBrainpoolP160r1PrivateKey` | `fp-curve` | weak |
| `brainpoolP160t1` | `BrainpoolP160t1` | `EcBrainpoolP160t1PublicKey` | `EcBrainpoolP160t1PrivateKey` | `fp-curve` | weak |
| `brainpoolP192r1` | `BrainpoolP192r1` | `EcBrainpoolP192r1PublicKey` | `EcBrainpoolP192r1PrivateKey` | `fp-curve` | weak |
| `brainpoolP192t1` | `BrainpoolP192t1` | `EcBrainpoolP192t1PublicKey` | `EcBrainpoolP192t1PrivateKey` | `fp-curve` | weak |
| `brainpoolP224r1` | `BrainpoolP224r1` | `EcBrainpoolP224r1PublicKey` | `EcBrainpoolP224r1PrivateKey` | `fp-curve` |  |
| `brainpoolP224t1` | `BrainpoolP224t1` | `EcBrainpoolP224t1PublicKey` | `EcBrainpoolP224t1PrivateKey` | `fp-curve` |  |
| `brainpoolP256r1` | `BrainpoolP256r1` | `EcBrainpoolP256r1PublicKey` | `EcBrainpoolP256r1PrivateKey` | `fp-curve` |  |
| `brainpoolP256t1` | `BrainpoolP256t1` | `EcBrainpoolP256t1PublicKey` | `EcBrainpoolP256t1PrivateKey` | `fp-curve` |  |
| `brainpoolP320r1` | `BrainpoolP320r1` | `EcBrainpoolP320r1PublicKey` | `EcBrainpoolP320r1PrivateKey` | `fp-curve` |  |
| `brainpoolP320t1` | `BrainpoolP320t1` | `EcBrainpoolP320t1PublicKey` | `EcBrainpoolP320t1PrivateKey` | `fp-curve` |  |
| `brainpoolP384r1` | `BrainpoolP384r1` | `EcBrainpoolP384r1PublicKey` | `EcBrainpoolP384r1PrivateKey` | `fp-curve` |  |
| `brainpoolP384t1` | `BrainpoolP384t1` | `EcBrainpoolP384t1PublicKey` | `EcBrainpoolP384t1PrivateKey` | `fp-curve` |  |
| `brainpoolP512r1` | `BrainpoolP512r1` | `EcBrainpoolP512r1PublicKey` | `EcBrainpoolP512r1PrivateKey` | `fp-curve` |  |
| `brainpoolP512t1` | `BrainpoolP512t1` | `EcBrainpoolP512t1PublicKey` | `EcBrainpoolP512t1PrivateKey` | `fp-curve` |  |
| `FRP256v1` | `FRP256v1` | `EcFRP256v1PublicKey` | `EcFRP256v1PrivateKey` | `fp-curve` |  |
| `GostR3410-2001-CryptoPro-A` | `GostR34102001CryptoProA` | `EcGostR34102001CryptoProAPublicKey` | `EcGostR34102001CryptoProAPrivateKey` | `fp-curve` |  |
| `GostR3410-2001-CryptoPro-B` | `GostR34102001CryptoProB` | `EcGostR34102001CryptoProBPublicKey` | `EcGostR34102001CryptoProBPrivateKey` | `fp-curve` |  |
| `GostR3410-2001-CryptoPro-C` | `GostR34102001CryptoProC` | `EcGostR34102001CryptoProCPublicKey` | `EcGostR34102001CryptoProCPrivateKey` | `fp-curve` |  |
| `GostR3410-2001-CryptoPro-XchA` | `GostR34102001CryptoProXchA` | `EcGostR34102001CryptoProXchAPublicKey` | `EcGostR34102001CryptoProXchAPrivateKey` | `fp-curve` |  |
| `GostR3410-2001-CryptoPro-XchB` | `GostR34102001CryptoProXchB` | `EcGostR34102001CryptoProXchBPublicKey` | `EcGostR34102001CryptoProXchBPrivateKey` | `fp-curve` |  |
| `Tc26-Gost-3410-12-256-paramSetA` | `Tc26Gost341012256ParamSetA` | `EcTc26Gost341012256ParamSetAPublicKey` | `EcTc26Gost341012256ParamSetAPrivateKey` | `fp-curve` |  |
| `Tc26-Gost-3410-12-256-paramSetB` | `Tc26Gost341012256ParamSetB` | `EcTc26Gost341012256ParamSetBPublicKey` | `EcTc26Gost341012256ParamSetBPrivateKey` | `fp-curve` |  |
| `Tc26-Gost-3410-12-256-paramSetC` | `Tc26Gost341012256ParamSetC` | `EcTc26Gost341012256ParamSetCPublicKey` | `EcTc26Gost341012256ParamSetCPrivateKey` | `fp-curve` |  |
| `Tc26-Gost-3410-12-256-paramSetD` | `Tc26Gost341012256ParamSetD` | `EcTc26Gost341012256ParamSetDPublicKey` | `EcTc26Gost341012256ParamSetDPrivateKey` | `fp-curve` |  |
| `Tc26-Gost-3410-12-512-paramSetA` | `Tc26Gost341012512ParamSetA` | `EcTc26Gost341012512ParamSetAPublicKey` | `EcTc26Gost341012512ParamSetAPrivateKey` | `fp-curve` |  |
| `Tc26-Gost-3410-12-512-paramSetB` | `Tc26Gost341012512ParamSetB` | `EcTc26Gost341012512ParamSetBPublicKey` | `EcTc26Gost341012512ParamSetBPrivateKey` | `fp-curve` |  |
| `Tc26-Gost-3410-12-512-paramSetC` | `Tc26Gost341012512ParamSetC` | `EcTc26Gost341012512ParamSetCPublicKey` | `EcTc26Gost341012512ParamSetCPrivateKey` | `fp-curve` |  |
| `wapip192v1` | `Wapip192v1` | `EcWapip192v1PublicKey` | `EcWapip192v1PrivateKey` | `fp-curve` | weak |
| `wapi192v1` | `Wapi192v1` | `EcWapi192v1PublicKey` | `EcWapi192v1PrivateKey` | `fp-curve` | weak |
| `sm2p256v1` | `Sm2p256v1` | `EcSm2p256v1PublicKey` | `EcSm2p256v1PrivateKey` | `fp-custom` |  |
| none | `Dstu4145Curve0` | `EcDstu4145Curve0PublicKey` | `EcDstu4145Curve0PrivateKey` | `f2m-curve` | weak |
| none | `Dstu4145Curve1` | `EcDstu4145Curve1PublicKey` | `EcDstu4145Curve1PrivateKey` | `f2m-curve` | weak |
| none | `Dstu4145Curve2` | `EcDstu4145Curve2PublicKey` | `EcDstu4145Curve2PrivateKey` | `f2m-curve` | weak |
| none | `Dstu4145Curve3` | `EcDstu4145Curve3PublicKey` | `EcDstu4145Curve3PrivateKey` | `f2m-curve` | weak |
| none | `Dstu4145Curve4` | `EcDstu4145Curve4PublicKey` | `EcDstu4145Curve4PrivateKey` | `f2m-curve` | weak |
| none | `Dstu4145Curve5` | `EcDstu4145Curve5PublicKey` | `EcDstu4145Curve5PrivateKey` | `f2m-curve` |  |
| none | `Dstu4145Curve6` | `EcDstu4145Curve6PublicKey` | `EcDstu4145Curve6PrivateKey` | `f2m-curve` |  |
| none | `Dstu4145Curve7` | `EcDstu4145Curve7PublicKey` | `EcDstu4145Curve7PrivateKey` | `f2m-curve` |  |
| none | `Dstu4145Curve8` | `EcDstu4145Curve8PublicKey` | `EcDstu4145Curve8PrivateKey` | `f2m-curve` |  |
| none | `Dstu4145Curve9` | `EcDstu4145Curve9PublicKey` | `EcDstu4145Curve9PrivateKey` | `f2m-curve` |  |

## Read and build a key pair

```rust
use tc_algo::params::generate::EcKeyGenParams;
use tc_algo::params::key::{EcSecp256r1PrivateKey, EcSecp256r1PublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = EcKeyGenParams::new("secp256r1");
    let pair = algo.key_pair_generator().generate_by_name_with("EC", &params)?;

    // The keys of secp256r1
    let public = pair
        .public()
        .as_any()
        .downcast_ref::<EcSecp256r1PublicKey>()
        .expect("an EcSecp256r1PublicKey");
    let private = pair
        .private()
        .as_any()
        .downcast_ref::<EcSecp256r1PrivateKey>()
        .expect("an EcSecp256r1PrivateKey");

    // Build the same keys again from their fields
    let _public1 = EcSecp256r1PublicKey::new(public.g().clone(), public.q())?;
    let _private1 = EcSecp256r1PrivateKey::new(private.g().clone(), private.d().clone())?;
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `SHA-256withECDSA` and the other ECDSA rows | Verifies | Signs |
| `<DIGEST>withECNR` and the `ECGOST3410` signers | Verifies | Signs |
| `ECDH`, `ECDHC` | The other side's key | Its own key |
| `ECMQV` | In `MqvPublicParams` | In `MqvPrivateParams` |
| The `ECGOST3410` agreement | The other side's key | In `EcVkoParams` |
| `ECIES` | The other side's key, in `IesEcParams` | Its own key, in `IesEcParams` |

The agreement rows with a KDF take the same keys, inside the params that
[Agreement](../Agreement.md#params) gives. A key goes only to a row of its own curve.

[Key pair generation](../KeyPairGeneration.md) · [EC](../Ec.md) ·
[EcKeyGenParams](../KeyPairGeneration/EcKeyGenParams.md)
