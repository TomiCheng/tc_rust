# X509Certificate

A certificate as received, after Bouncy Castle's `X509Certificate`: the fields it holds, its
encoding, and the check of its signature.

## Reading a certificate

From the bytes of a certificate to its fields, its public key and its signature:

```rust
use tc_asn1_x509::ext::BasicConstraints;
use tc_x509::cert::{X509Certificate, X509V3CertificateGenerator};
use tc_x509::operator::params::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509OperatorBuilder};

fn main() -> Result<(), X509Error> {
    let oper = DefaultX509OperatorBuilder::default().build();

    // A self-signed certificate, to have some bytes to read
    let mut key_gen = oper.key_pair_generator().get_by_name("RSA")?;
    key_gen.init(&RsaKeyGenParams::new(2048))?;
    let (public, private) = key_gen.generate()?.into_parts();
    let mut generator = X509V3CertificateGenerator::new();
    generator.set_issuer_by_str("CN=My CA")?;
    generator.set_subject_by_str("CN=My CA")?;
    generator.set_validity_days(365)?;
    generator.set_subject_public_key_info(oper.spki().encode(public.as_ref())?);
    generator.add_basic_constraints(BasicConstraints::ca(None))?;
    let factory = oper.signature_factory("SHA-256withRSA", private.into())?;
    let bytes = generator.generate(factory.as_ref())?.encode()?;

    // Decode the bytes, and read the fields
    let certificate = X509Certificate::decode(&bytes)?;
    assert_eq!(certificate.subject().to_string(), "CN=My CA");

    // The public key it holds
    let key = oper.spki().decode(certificate.subject_public_key_info())?;

    // Self-signed, so the issuer's key is its own
    let provider = oper.verifier_factory_provider(key.into());
    certificate.verify(provider.as_ref())?;

    // Back to the same bytes
    assert_eq!(certificate.encode()?, bytes);
    Ok(())
}
```

Only two steps depend on the algorithm, the public key and the signature, so only they go through
the operator. The certificate is a plain type that holds the fields.

## Methods

| Method | Bouncy Castle |
|---|---|
| `decode`, `decode_from`, `new` | the constructors |
| `encode`, `encode_to` | `GetEncoded` |
| `version`, `serial_number`, `issuer`, `subject`, `not_before`, `not_after` | the properties of the same names |
| `is_valid_at` | `IsValid` |
| `tbs_certificate`, `signature`, `signature_algorithm` | `GetTbsCertificate`, `GetSignature`, `SignatureAlgorithm` |
| `subject_public_key_info` | `SubjectPublicKeyInfo` |
| `is_signature_valid`, `verify` | `IsSignatureValid`, `Verify` |
| `issuer_unique_id`, `subject_unique_id`, `extensions` | the properties of the same names |
| `certificate` | `CertificateStructure` |

## Using it

- `decode` takes one certificate in BER or DER; bytes after it are `TrailingData`.
  `decode_from` reads one from a stream and nothing past it, `None` at its end, and
  `encode_to` writes the DER to one.
- `encode` writes DER, but the signed part as received, so that the signature stays valid. A
  certificate received in BER keeps that part in BER.
- The public key is decoded anew on each call to `oper.spki().decode`, a key of its own that
  outlives the certificate. To use it more than once, decode it once and share it through an
  `Arc`.
- The signature is checked with the key of the issuer: its own for a self-signed certificate, the
  key in the issuer's certificate for any other.
- `is_signature_valid` is `false` for a signature that does not verify, and `verify` is
  `InvalidSignature`. Both are `AlgorithmMismatch` when the signature algorithm inside the signed
  part differs from the one outside it, and `UnknownSigner` when no row knows it.
- Only the signature is checked; the validity period is `is_valid_at`, and the path to a trusted
  certificate is not checked here.
