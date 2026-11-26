# EcKeyGenParams

## Generate a key pair

The following example uses `P-256` (requires the `fp-custom` feature):

```rust
use tc_algo::params::generate::EcKeyGenParams;
use tc_algo::params::key::{EcSecp256r1PrivateKey, EcSecp256r1PublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = EcKeyGenParams::new("P-256");
    let pair = algo.key_pair_generator().generate_by_name_with("EC", &params)?;

    let _public = pair.public().as_any().downcast_ref::<EcSecp256r1PublicKey>().expect("an EcPublicKey");
    let _private = pair.private().as_any().downcast_ref::<EcSecp256r1PrivateKey>().expect("an EcPrivateKey");
    Ok(())
}
```

The generator returns a `KeyPair` whose `public()` and `private()` keys are `EcPublicKey<C>`
and `EcPrivateKey<C>` inside `Box<dyn Params>`, where `C` is the curve's static type.
`tc_algo::params::key` names `C` and both key types for every named curve, after its SEC or
first name: `Secp256r1`, `EcSecp256r1PublicKey` and `EcSecp256r1PrivateKey` for P-256. Curves
that share a field share a type, as `Sect163k1` and `Sect163r2` do, and so do all the curves of
`fp-curve`, and of `f2m-curve`: a downcast tells such curves apart only by the key's parameters.

Enable at least one curve feature (`fp-custom`, `fp-curve`, `f2m-custom`, or `f2m-curve`;
each also enables `ec-key`) to use the `EC` key pair generator. Import `EcKeyGenParams` from
`tc_algo::params::generate`.

| Method | Setting | Valid input |
|---|---|---|
| `new(name)` | Selects a curve by name (case-insensitive) | Any named curve in the enabled curve features (e.g. `"P-256"`, `"secp256r1"`, `"prime256v1"`) |
| `from_oid(oid)` | Selects a curve by `Asn1Oid` | Any curve OID in the enabled curve features (required for unnamed curves such as DSTU 4145) |

`EC` has no default curve, so `generate_by_name("EC")` returns `NotInitialized`. Construction
validates nothing: `init` looks up the curve among the enabled curve features and returns
`InvalidParams` if the curve is unknown or its feature is not enabled. The curves are listed
below.

## Curves

The names and OIDs are those of Bouncy Castle's `ECNamedCurveTable`, which joins X9.62, SEC,
NIST, TeleTrusT, ANSSI, GOST and GM, and the curves of DSTU 4145, which Bouncy Castle gives by
OID alone. A curve with a special form of its own runs on the faster arithmetic of
`tc_fp_custom` or `tc_f2m_custom`, the others on the generic one of `tc_fp_curve` or
`tc_f2m_curve`, all in constant time. The last three columns are the aliases in
`tc_algo::params::key` that name the curve type `C` and the two key types over it. A weak curve
has an order below 224 bits, so less than the 112 bits of security that NIST SP 800-57 asks
for; it is here to read old keys and data, not for new ones.

| Names | OID | Feature | Curve type `C` | Public key | Private key | Note |
|---|---|---|---|---|---|---|
| `secp112r1` | `1.3.132.0.6` | `fp-curve` | `Secp112r1` | `EcSecp112r1PublicKey` | `EcSecp112r1PrivateKey` | weak |
| `secp112r2` | `1.3.132.0.7` | `fp-curve` | `Secp112r2` | `EcSecp112r2PublicKey` | `EcSecp112r2PrivateKey` | weak |
| `secp128r1` | `1.3.132.0.28` | `fp-custom` | `Secp128r1` | `EcSecp128r1PublicKey` | `EcSecp128r1PrivateKey` | weak |
| `secp128r2` | `1.3.132.0.29` | `fp-curve` | `Secp128r2` | `EcSecp128r2PublicKey` | `EcSecp128r2PrivateKey` | weak |
| `secp160k1` | `1.3.132.0.9` | `fp-custom` | `Secp160k1` | `EcSecp160k1PublicKey` | `EcSecp160k1PrivateKey` | weak |
| `secp160r1` | `1.3.132.0.8` | `fp-custom` | `Secp160r1` | `EcSecp160r1PublicKey` | `EcSecp160r1PrivateKey` | weak |
| `secp160r2` | `1.3.132.0.30` | `fp-custom` | `Secp160r2` | `EcSecp160r2PublicKey` | `EcSecp160r2PrivateKey` | weak |
| `secp192k1` | `1.3.132.0.31` | `fp-custom` | `Secp192k1` | `EcSecp192k1PublicKey` | `EcSecp192k1PrivateKey` | weak |
| `secp192r1`, `prime192v1`, `P-192` | `1.2.840.10045.3.1.1` | `fp-custom` | `Secp192r1` | `EcSecp192r1PublicKey` | `EcSecp192r1PrivateKey` | weak |
| `secp224k1` | `1.3.132.0.32` | `fp-custom` | `Secp224k1` | `EcSecp224k1PublicKey` | `EcSecp224k1PrivateKey` |  |
| `secp224r1`, `P-224` | `1.3.132.0.33` | `fp-custom` | `Secp224r1` | `EcSecp224r1PublicKey` | `EcSecp224r1PrivateKey` |  |
| `secp256k1` | `1.3.132.0.10` | `fp-custom` | `Secp256k1` | `EcSecp256k1PublicKey` | `EcSecp256k1PrivateKey` |  |
| `secp256r1`, `prime256v1`, `P-256` | `1.2.840.10045.3.1.7` | `fp-custom` | `Secp256r1` | `EcSecp256r1PublicKey` | `EcSecp256r1PrivateKey` |  |
| `secp384r1`, `P-384` | `1.3.132.0.34` | `fp-custom` | `Secp384r1` | `EcSecp384r1PublicKey` | `EcSecp384r1PrivateKey` |  |
| `secp521r1`, `P-521` | `1.3.132.0.35` | `fp-custom` | `Secp521r1` | `EcSecp521r1PublicKey` | `EcSecp521r1PrivateKey` |  |
| `sect113r1` | `1.3.132.0.4` | `f2m-custom` | `Sect113r1` | `EcSect113r1PublicKey` | `EcSect113r1PrivateKey` | weak |
| `sect113r2` | `1.3.132.0.5` | `f2m-custom` | `Sect113r2` | `EcSect113r2PublicKey` | `EcSect113r2PrivateKey` | weak |
| `sect131r1` | `1.3.132.0.22` | `f2m-custom` | `Sect131r1` | `EcSect131r1PublicKey` | `EcSect131r1PrivateKey` | weak |
| `sect131r2` | `1.3.132.0.23` | `f2m-custom` | `Sect131r2` | `EcSect131r2PublicKey` | `EcSect131r2PrivateKey` | weak |
| `sect163k1`, `K-163` | `1.3.132.0.1` | `f2m-custom` | `Sect163k1` | `EcSect163k1PublicKey` | `EcSect163k1PrivateKey` | weak |
| `sect163r1` | `1.3.132.0.2` | `f2m-custom` | `Sect163r1` | `EcSect163r1PublicKey` | `EcSect163r1PrivateKey` | weak |
| `sect163r2`, `B-163` | `1.3.132.0.15` | `f2m-custom` | `Sect163r2` | `EcSect163r2PublicKey` | `EcSect163r2PrivateKey` | weak |
| `sect193r1` | `1.3.132.0.24` | `f2m-custom` | `Sect193r1` | `EcSect193r1PublicKey` | `EcSect193r1PrivateKey` | weak |
| `sect193r2` | `1.3.132.0.25` | `f2m-custom` | `Sect193r2` | `EcSect193r2PublicKey` | `EcSect193r2PrivateKey` | weak |
| `sect233k1`, `K-233` | `1.3.132.0.26` | `f2m-custom` | `Sect233k1` | `EcSect233k1PublicKey` | `EcSect233k1PrivateKey` |  |
| `sect233r1`, `B-233` | `1.3.132.0.27` | `f2m-custom` | `Sect233r1` | `EcSect233r1PublicKey` | `EcSect233r1PrivateKey` |  |
| `sect239k1` | `1.3.132.0.3` | `f2m-custom` | `Sect239k1` | `EcSect239k1PublicKey` | `EcSect239k1PrivateKey` |  |
| `sect283k1`, `K-283` | `1.3.132.0.16` | `f2m-custom` | `Sect283k1` | `EcSect283k1PublicKey` | `EcSect283k1PrivateKey` |  |
| `sect283r1`, `B-283` | `1.3.132.0.17` | `f2m-custom` | `Sect283r1` | `EcSect283r1PublicKey` | `EcSect283r1PrivateKey` |  |
| `sect409k1`, `K-409` | `1.3.132.0.36` | `f2m-custom` | `Sect409k1` | `EcSect409k1PublicKey` | `EcSect409k1PrivateKey` |  |
| `sect409r1`, `B-409` | `1.3.132.0.37` | `f2m-custom` | `Sect409r1` | `EcSect409r1PublicKey` | `EcSect409r1PrivateKey` |  |
| `sect571k1`, `K-571` | `1.3.132.0.38` | `f2m-custom` | `Sect571k1` | `EcSect571k1PublicKey` | `EcSect571k1PrivateKey` |  |
| `sect571r1`, `B-571` | `1.3.132.0.39` | `f2m-custom` | `Sect571r1` | `EcSect571r1PublicKey` | `EcSect571r1PrivateKey` |  |
| `prime192v2` | `1.2.840.10045.3.1.2` | `fp-curve` | `Prime192v2` | `EcPrime192v2PublicKey` | `EcPrime192v2PrivateKey` | weak |
| `prime192v3` | `1.2.840.10045.3.1.3` | `fp-curve` | `Prime192v3` | `EcPrime192v3PublicKey` | `EcPrime192v3PrivateKey` | weak |
| `prime239v1` | `1.2.840.10045.3.1.4` | `fp-curve` | `Prime239v1` | `EcPrime239v1PublicKey` | `EcPrime239v1PrivateKey` |  |
| `prime239v2` | `1.2.840.10045.3.1.5` | `fp-curve` | `Prime239v2` | `EcPrime239v2PublicKey` | `EcPrime239v2PrivateKey` |  |
| `prime239v3` | `1.2.840.10045.3.1.6` | `fp-curve` | `Prime239v3` | `EcPrime239v3PublicKey` | `EcPrime239v3PrivateKey` |  |
| `c2pnb163v1` | `1.2.840.10045.3.0.1` | `f2m-curve` | `C2pnb163v1` | `EcC2pnb163v1PublicKey` | `EcC2pnb163v1PrivateKey` | weak |
| `c2pnb163v2` | `1.2.840.10045.3.0.2` | `f2m-curve` | `C2pnb163v2` | `EcC2pnb163v2PublicKey` | `EcC2pnb163v2PrivateKey` | weak |
| `c2pnb163v3` | `1.2.840.10045.3.0.3` | `f2m-curve` | `C2pnb163v3` | `EcC2pnb163v3PublicKey` | `EcC2pnb163v3PrivateKey` | weak |
| `c2pnb176w1` | `1.2.840.10045.3.0.4` | `f2m-curve` | `C2pnb176w1` | `EcC2pnb176w1PublicKey` | `EcC2pnb176w1PrivateKey` | weak |
| `c2tnb191v1` | `1.2.840.10045.3.0.5` | `f2m-curve` | `C2tnb191v1` | `EcC2tnb191v1PublicKey` | `EcC2tnb191v1PrivateKey` | weak |
| `c2tnb191v2` | `1.2.840.10045.3.0.6` | `f2m-curve` | `C2tnb191v2` | `EcC2tnb191v2PublicKey` | `EcC2tnb191v2PrivateKey` | weak |
| `c2tnb191v3` | `1.2.840.10045.3.0.7` | `f2m-curve` | `C2tnb191v3` | `EcC2tnb191v3PublicKey` | `EcC2tnb191v3PrivateKey` | weak |
| `c2pnb208w1` | `1.2.840.10045.3.0.10` | `f2m-curve` | `C2pnb208w1` | `EcC2pnb208w1PublicKey` | `EcC2pnb208w1PrivateKey` | weak |
| `c2tnb239v1` | `1.2.840.10045.3.0.11` | `f2m-curve` | `C2tnb239v1` | `EcC2tnb239v1PublicKey` | `EcC2tnb239v1PrivateKey` |  |
| `c2tnb239v2` | `1.2.840.10045.3.0.12` | `f2m-curve` | `C2tnb239v2` | `EcC2tnb239v2PublicKey` | `EcC2tnb239v2PrivateKey` |  |
| `c2tnb239v3` | `1.2.840.10045.3.0.13` | `f2m-curve` | `C2tnb239v3` | `EcC2tnb239v3PublicKey` | `EcC2tnb239v3PrivateKey` |  |
| `c2pnb272w1` | `1.2.840.10045.3.0.16` | `f2m-curve` | `C2pnb272w1` | `EcC2pnb272w1PublicKey` | `EcC2pnb272w1PrivateKey` |  |
| `c2pnb304w1` | `1.2.840.10045.3.0.17` | `f2m-curve` | `C2pnb304w1` | `EcC2pnb304w1PublicKey` | `EcC2pnb304w1PrivateKey` |  |
| `c2tnb359v1` | `1.2.840.10045.3.0.18` | `f2m-curve` | `C2tnb359v1` | `EcC2tnb359v1PublicKey` | `EcC2tnb359v1PrivateKey` |  |
| `c2pnb368w1` | `1.2.840.10045.3.0.19` | `f2m-curve` | `C2pnb368w1` | `EcC2pnb368w1PublicKey` | `EcC2pnb368w1PrivateKey` |  |
| `c2tnb431r1` | `1.2.840.10045.3.0.20` | `f2m-curve` | `C2tnb431r1` | `EcC2tnb431r1PublicKey` | `EcC2tnb431r1PrivateKey` |  |
| `brainpoolP160r1` | `1.3.36.3.3.2.8.1.1.1` | `fp-curve` | `BrainpoolP160r1` | `EcBrainpoolP160r1PublicKey` | `EcBrainpoolP160r1PrivateKey` | weak |
| `brainpoolP160t1` | `1.3.36.3.3.2.8.1.1.2` | `fp-curve` | `BrainpoolP160t1` | `EcBrainpoolP160t1PublicKey` | `EcBrainpoolP160t1PrivateKey` | weak |
| `brainpoolP192r1` | `1.3.36.3.3.2.8.1.1.3` | `fp-curve` | `BrainpoolP192r1` | `EcBrainpoolP192r1PublicKey` | `EcBrainpoolP192r1PrivateKey` | weak |
| `brainpoolP192t1` | `1.3.36.3.3.2.8.1.1.4` | `fp-curve` | `BrainpoolP192t1` | `EcBrainpoolP192t1PublicKey` | `EcBrainpoolP192t1PrivateKey` | weak |
| `brainpoolP224r1` | `1.3.36.3.3.2.8.1.1.5` | `fp-curve` | `BrainpoolP224r1` | `EcBrainpoolP224r1PublicKey` | `EcBrainpoolP224r1PrivateKey` |  |
| `brainpoolP224t1` | `1.3.36.3.3.2.8.1.1.6` | `fp-curve` | `BrainpoolP224t1` | `EcBrainpoolP224t1PublicKey` | `EcBrainpoolP224t1PrivateKey` |  |
| `brainpoolP256r1` | `1.3.36.3.3.2.8.1.1.7` | `fp-curve` | `BrainpoolP256r1` | `EcBrainpoolP256r1PublicKey` | `EcBrainpoolP256r1PrivateKey` |  |
| `brainpoolP256t1` | `1.3.36.3.3.2.8.1.1.8` | `fp-curve` | `BrainpoolP256t1` | `EcBrainpoolP256t1PublicKey` | `EcBrainpoolP256t1PrivateKey` |  |
| `brainpoolP320r1` | `1.3.36.3.3.2.8.1.1.9` | `fp-curve` | `BrainpoolP320r1` | `EcBrainpoolP320r1PublicKey` | `EcBrainpoolP320r1PrivateKey` |  |
| `brainpoolP320t1` | `1.3.36.3.3.2.8.1.1.10` | `fp-curve` | `BrainpoolP320t1` | `EcBrainpoolP320t1PublicKey` | `EcBrainpoolP320t1PrivateKey` |  |
| `brainpoolP384r1` | `1.3.36.3.3.2.8.1.1.11` | `fp-curve` | `BrainpoolP384r1` | `EcBrainpoolP384r1PublicKey` | `EcBrainpoolP384r1PrivateKey` |  |
| `brainpoolP384t1` | `1.3.36.3.3.2.8.1.1.12` | `fp-curve` | `BrainpoolP384t1` | `EcBrainpoolP384t1PublicKey` | `EcBrainpoolP384t1PrivateKey` |  |
| `brainpoolP512r1` | `1.3.36.3.3.2.8.1.1.13` | `fp-curve` | `BrainpoolP512r1` | `EcBrainpoolP512r1PublicKey` | `EcBrainpoolP512r1PrivateKey` |  |
| `brainpoolP512t1` | `1.3.36.3.3.2.8.1.1.14` | `fp-curve` | `BrainpoolP512t1` | `EcBrainpoolP512t1PublicKey` | `EcBrainpoolP512t1PrivateKey` |  |
| `FRP256v1` | `1.2.250.1.223.101.256.1` | `fp-curve` | `FRP256v1` | `EcFRP256v1PublicKey` | `EcFRP256v1PrivateKey` |  |
| `GostR3410-2001-CryptoPro-A` | `1.2.643.2.2.35.1` | `fp-curve` | `GostR34102001CryptoProA` | `EcGostR34102001CryptoProAPublicKey` | `EcGostR34102001CryptoProAPrivateKey` |  |
| `GostR3410-2001-CryptoPro-B` | `1.2.643.2.2.35.2` | `fp-curve` | `GostR34102001CryptoProB` | `EcGostR34102001CryptoProBPublicKey` | `EcGostR34102001CryptoProBPrivateKey` |  |
| `GostR3410-2001-CryptoPro-C` | `1.2.643.2.2.35.3` | `fp-curve` | `GostR34102001CryptoProC` | `EcGostR34102001CryptoProCPublicKey` | `EcGostR34102001CryptoProCPrivateKey` |  |
| `GostR3410-2001-CryptoPro-XchA` | `1.2.643.2.2.36.0` | `fp-curve` | `GostR34102001CryptoProXchA` | `EcGostR34102001CryptoProXchAPublicKey` | `EcGostR34102001CryptoProXchAPrivateKey` |  |
| `GostR3410-2001-CryptoPro-XchB` | `1.2.643.2.2.36.1` | `fp-curve` | `GostR34102001CryptoProXchB` | `EcGostR34102001CryptoProXchBPublicKey` | `EcGostR34102001CryptoProXchBPrivateKey` |  |
| `Tc26-Gost-3410-12-256-paramSetA` | `1.2.643.7.1.2.1.1.1` | `fp-curve` | `Tc26Gost341012256ParamSetA` | `EcTc26Gost341012256ParamSetAPublicKey` | `EcTc26Gost341012256ParamSetAPrivateKey` |  |
| `Tc26-Gost-3410-12-256-paramSetB` | `1.2.643.7.1.2.1.1.2` | `fp-curve` | `Tc26Gost341012256ParamSetB` | `EcTc26Gost341012256ParamSetBPublicKey` | `EcTc26Gost341012256ParamSetBPrivateKey` |  |
| `Tc26-Gost-3410-12-256-paramSetC` | `1.2.643.7.1.2.1.1.3` | `fp-curve` | `Tc26Gost341012256ParamSetC` | `EcTc26Gost341012256ParamSetCPublicKey` | `EcTc26Gost341012256ParamSetCPrivateKey` |  |
| `Tc26-Gost-3410-12-256-paramSetD` | `1.2.643.7.1.2.1.1.4` | `fp-curve` | `Tc26Gost341012256ParamSetD` | `EcTc26Gost341012256ParamSetDPublicKey` | `EcTc26Gost341012256ParamSetDPrivateKey` |  |
| `Tc26-Gost-3410-12-512-paramSetA` | `1.2.643.7.1.2.1.2.1` | `fp-curve` | `Tc26Gost341012512ParamSetA` | `EcTc26Gost341012512ParamSetAPublicKey` | `EcTc26Gost341012512ParamSetAPrivateKey` |  |
| `Tc26-Gost-3410-12-512-paramSetB` | `1.2.643.7.1.2.1.2.2` | `fp-curve` | `Tc26Gost341012512ParamSetB` | `EcTc26Gost341012512ParamSetBPublicKey` | `EcTc26Gost341012512ParamSetBPrivateKey` |  |
| `Tc26-Gost-3410-12-512-paramSetC` | `1.2.643.7.1.2.1.2.3` | `fp-curve` | `Tc26Gost341012512ParamSetC` | `EcTc26Gost341012512ParamSetCPublicKey` | `EcTc26Gost341012512ParamSetCPrivateKey` |  |
| `wapip192v1` | `1.2.156.10197.1.301.101` | `fp-curve` | `Wapip192v1` | `EcWapip192v1PublicKey` | `EcWapip192v1PrivateKey` | weak |
| `wapi192v1` | `1.2.156.11235.1.1.1` | `fp-curve` | `Wapi192v1` | `EcWapi192v1PublicKey` | `EcWapi192v1PrivateKey` | weak |
| `sm2p256v1` | `1.2.156.10197.1.301` | `fp-custom` | `Sm2p256v1` | `EcSm2p256v1PublicKey` | `EcSm2p256v1PrivateKey` |  |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.0` | `f2m-curve` | `Dstu4145Curve0` | `EcDstu4145Curve0PublicKey` | `EcDstu4145Curve0PrivateKey` | weak |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.1` | `f2m-curve` | `Dstu4145Curve1` | `EcDstu4145Curve1PublicKey` | `EcDstu4145Curve1PrivateKey` | weak |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.2` | `f2m-curve` | `Dstu4145Curve2` | `EcDstu4145Curve2PublicKey` | `EcDstu4145Curve2PrivateKey` | weak |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.3` | `f2m-curve` | `Dstu4145Curve3` | `EcDstu4145Curve3PublicKey` | `EcDstu4145Curve3PrivateKey` | weak |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.4` | `f2m-curve` | `Dstu4145Curve4` | `EcDstu4145Curve4PublicKey` | `EcDstu4145Curve4PrivateKey` | weak |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.5` | `f2m-curve` | `Dstu4145Curve5` | `EcDstu4145Curve5PublicKey` | `EcDstu4145Curve5PrivateKey` |  |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.6` | `f2m-curve` | `Dstu4145Curve6` | `EcDstu4145Curve6PublicKey` | `EcDstu4145Curve6PrivateKey` |  |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.7` | `f2m-curve` | `Dstu4145Curve7` | `EcDstu4145Curve7PublicKey` | `EcDstu4145Curve7PrivateKey` |  |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.8` | `f2m-curve` | `Dstu4145Curve8` | `EcDstu4145Curve8PublicKey` | `EcDstu4145Curve8PrivateKey` |  |
| none | `1.2.804.2.1.1.1.1.3.1.1.2.9` | `f2m-curve` | `Dstu4145Curve9` | `EcDstu4145Curve9PublicKey` | `EcDstu4145Curve9PrivateKey` |  |

[Key pair generation](../KeyPairGeneration.md) · [EC](../Ec.md)
