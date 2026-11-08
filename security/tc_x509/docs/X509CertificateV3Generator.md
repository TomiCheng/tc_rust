# X509CertificateV3Generator

Generates version 3 X.509 certificates, after Bouncy Castle's `X509V3CertificateGenerator`.

> **Status:** generating the key pair and turning its public key into a `SubjectPublicKeyInfo`
> work. The signer and the generator are a design, so the example below does not compile yet.

## Generating a certificate

From a new key pair to a self-signed certificate:

```rust,ignore
let oper = DefaultX509OperatorBuilder::default().build();

// Generate a pair
let mut key_gen = oper.key_pair_generator().get_by_name("RSA")?;
key_gen.init(&RsaKeyGenParams::new(2048))?;
let pair = key_gen.generate()?;

// The public key, as a certificate holds it
let spki = oper.spki().encode(pair.public())?;

// Sign with the private key
let signer = oper.signer().get_by_name("SHA-256withRSA", pair.private())?;

// Fill in the fields, and sign
let mut generator = X509V3CertificateGenerator::new();
generator.set_serial_number(serial)?;
generator.set_issuer(name.clone());
generator.set_validity(validity);
generator.set_subject(name);
generator.set_subject_public_key_info(spki);
let certificate = generator.generate(signer.as_ref())?;
```

Only two steps depend on the algorithm, the public key and the signature, so only they go through
the operator. The generator is a plain type that holds the fields.

## Fields

| Set by | Required |
|---|---|
| `set_serial_number` | no: a random one of 16 bytes is made when it is not set |
| `set_issuer` | yes |
| `set_validity` | yes |
| `set_subject` | yes, unless a critical subject alternative name is present |
| `set_subject_public_key_info` | yes |
| `add_extension` | no |

The signature algorithm comes from the signer, and goes into the signed part of the certificate.

## Using it

- `oper.spki().encode` takes any public key a row knows, RSA among the built-in ones. A private key
  is `NotPublicKey`, and a key no row knows is `UnknownPublicKey`.
- `set_serial_number` is `InvalidSerialNumber` unless the number is positive, as Bouncy Castle
  checks. The other `set_` methods only store what they are given. `generate` reports a missing
  field.
- Without a serial number, each certificate generated is different, so a test that needs the same
  certificate each time sets one.
- An extension may appear only once in a certificate, as RFC 5280 section 4.2 requires.
- The issuer signs: a self-signed certificate uses the private key of its own pair, and any other
  uses the private key of the issuer.
- A key that cannot sign, such as DH, can be the subject's but not the issuer's.
