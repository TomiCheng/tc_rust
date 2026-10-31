//! `DsaDigestSigner` 與兩種編碼：RFC 6979 A.2.5（P-256、SHA-256、"sample"）的 (r, s) 以
//! Plain 與 DER 編碼；DER 解碼只收嚴格的 DER；值的範圍；以及錯誤。

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{
    DsaDigestSigner, DsaDigestSignerError, DsaEncoding, DsaEncodingError, HMacDsaKCalculator,
    PlainDsaEncoding, StandardDsaEncoding,
};
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_ecdsa_v2::EcdsaSigner;
use tc_fp_custom::named_curves::SECP256R1;
use tc_fp_custom::{SecP256R1FieldElement, SecPCtCurve};
use tc_sha::Sha256Digest;
use tc_signer::{Signer, SignerInit};

type P256<'a> = &'a SecPCtCurve<SecP256R1FieldElement>;

const D: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
const R: &str = "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716";
const S: &str = "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
const N: &str = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn integer(hex: &str) -> PaddedBigUint {
    let Ok(value) = PaddedBigUint::from_be(&bytes(hex));
    value
}

fn ecdsa<'a>() -> EcdsaSigner<P256<'a>, HMacDsaKCalculator<Sha256Digest>> {
    EcdsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()))
}

fn sign<N2: DsaEncoding>(encoding: N2) -> Vec<u8> {
    let curve = SECP256R1.ct_curve();
    let g = SECP256R1.ct_generator(&curve);
    let mut signer = DsaDigestSigner::with_encoding(ecdsa(), Sha256Digest::new(), encoding);
    signer
        .init(&EcPrivateKey::<P256<'_>>::new(g, integer(D)).unwrap())
        .unwrap();
    signer.update(b"sample").unwrap();
    let mut signature = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut signature).unwrap();
    signature.truncate(length);
    signature
}

fn verify<N2: DsaEncoding>(encoding: N2, message: &[u8], signature: &[u8]) -> bool {
    let curve = SECP256R1.ct_curve();
    let g = SECP256R1.ct_generator(&curve);
    let q = <P256<'_>>::multiply(&g, &integer(D));
    let mut verifier = DsaDigestSigner::with_encoding(ecdsa(), Sha256Digest::new(), encoding);
    verifier
        .init(&EcPublicKey::<P256<'_>>::new(g, &q).unwrap())
        .unwrap();
    verifier.update(message).unwrap();
    verifier.verify_signature(signature).unwrap()
}

#[test]
fn rfc_6979_p256_signs_as_r_then_s_in_the_plain_encoding() {
    let signature = sign(PlainDsaEncoding);
    assert_eq!(signature, [bytes(R), bytes(S)].concat());
    assert!(verify(PlainDsaEncoding, b"sample", &signature));
    assert!(!verify(PlainDsaEncoding, b"test", &signature));
}

#[test]
fn rfc_6979_p256_signs_as_a_der_sequence_by_default() {
    let expected = [bytes("3046022100"), bytes(R), bytes("022100"), bytes(S)].concat();
    let curve = SECP256R1.ct_curve();
    let g = SECP256R1.ct_generator(&curve);
    let mut signer = DsaDigestSigner::new(ecdsa(), Sha256Digest::new());
    signer
        .init(&EcPrivateKey::<P256<'_>>::new(g, integer(D)).unwrap())
        .unwrap();
    assert_eq!(signer.max_signature_size(), 72);
    signer.update(b"sample").unwrap();
    let mut signature = vec![0; 72];
    let length = signer.generate_signature(&mut signature).unwrap();
    assert_eq!(signature[..length], expected[..]);
    assert!(verify(StandardDsaEncoding, b"sample", &expected));
    assert!(!verify(PlainDsaEncoding, b"sample", &expected));
}

#[test]
fn der_decoding_accepts_only_strict_der_with_values_below_the_order() {
    let n = integer(N);
    let der = [bytes("3046022100"), bytes(R), bytes("022100"), bytes(S)].concat();
    assert_eq!(
        StandardDsaEncoding.decode(&n, &der),
        Ok((integer(R), integer(S)))
    );
    for malformed in [
        // 多餘的位元組。
        [der.clone(), vec![0]].concat(),
        // 長度以兩個位元組寫，不是 DER。
        [bytes("308146022100"), bytes(R), bytes("022100"), bytes(S)].concat(),
        // 多一個前導零，不是最短的 INTEGER。
        [
            bytes("3047022200"),
            bytes("00"),
            bytes(R),
            bytes("022100"),
            bytes(S),
        ]
        .concat(),
        // 只有一個 INTEGER。
        [bytes("3023022100"), bytes(R)].concat(),
    ] {
        assert_eq!(
            StandardDsaEncoding.decode(&n, &malformed),
            Err(DsaEncodingError::Malformed)
        );
    }
    // 負數與不小於 n 的值。
    let negative = [bytes("30250220"), bytes(R), bytes("020101")].concat();
    assert_eq!(
        StandardDsaEncoding.decode(&n, &negative),
        Err(DsaEncodingError::ValueOutOfRange)
    );
    let too_large = [bytes("3046022100"), bytes(N), bytes("022100"), bytes(S)].concat();
    assert_eq!(
        StandardDsaEncoding.decode(&n, &too_large),
        Err(DsaEncodingError::ValueOutOfRange)
    );
}

#[test]
fn plain_decoding_needs_twice_the_order_length_and_values_below_it() {
    let n = integer(N);
    let plain = [bytes(R), bytes(S)].concat();
    assert_eq!(
        PlainDsaEncoding.decode(&n, &plain),
        Ok((integer(R), integer(S)))
    );
    assert_eq!(
        PlainDsaEncoding.decode(&n, &plain[1..]),
        Err(DsaEncodingError::Malformed)
    );
    let too_large = [bytes(N), bytes(S)].concat();
    assert_eq!(
        PlainDsaEncoding.decode(&n, &too_large),
        Err(DsaEncodingError::ValueOutOfRange)
    );
    assert_eq!(
        PlainDsaEncoding.encode(&n, &integer(R), &integer(S), &mut [0; 63]),
        Err(DsaEncodingError::OutputTooShort)
    );
    // 短的值前面補零。
    let mut output = [0xff; 64];
    PlainDsaEncoding
        .encode(
            &n,
            &PaddedBigUint::from(1u8),
            &PaddedBigUint::from(2u8),
            &mut output,
        )
        .unwrap();
    assert_eq!(output[..32], [vec![0; 31], vec![1]].concat()[..]);
    assert_eq!(output[32..], [vec![0; 31], vec![2]].concat()[..]);
}

#[test]
fn errors_are_reported() {
    let curve = SECP256R1.ct_curve();
    let g = SECP256R1.ct_generator(&curve);
    let q = <P256<'_>>::multiply(&g, &integer(D));
    let mut signer = DsaDigestSigner::new(ecdsa(), Sha256Digest::new());
    assert_eq!(
        signer.update(b"x"),
        Err(DsaDigestSignerError::NotInitialized)
    );
    signer
        .init(&EcPublicKey::<P256<'_>>::new(g.clone(), &q).unwrap())
        .unwrap();
    assert_eq!(
        signer.generate_signature(&mut [0; 72]),
        Err(DsaDigestSignerError::NotForSigning)
    );
    // 解不出的簽章視為不符。
    assert!(!signer.verify_signature(&[0x30, 0x00]).unwrap());
    signer
        .init(&EcPrivateKey::<P256<'_>>::new(g, integer(D)).unwrap())
        .unwrap();
    assert_eq!(
        signer.verify_signature(&[0; 72]),
        Err(DsaDigestSignerError::NotForVerifying)
    );
    assert_eq!(
        signer.generate_signature(&mut [0; 10]),
        Err(DsaDigestSignerError::Encoding(
            DsaEncodingError::OutputTooShort
        ))
    );
}
