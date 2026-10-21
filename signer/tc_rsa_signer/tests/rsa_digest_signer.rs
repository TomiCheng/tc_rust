use num_traits::Num;
use tc_asn1::{Encode, EncodingOptions};
use tc_asn1_pkcs::Pkcs1Algorithm;
use tc_asn1_x509::alg::{AlgorithmIdentifier, DigestInfo};
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_asym_encoding::Pkcs1Encoding;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_rsa::{RsaEngine, RsaKey, RsaKeyOwned, RsaPrivateCrtKeyOwned};
use tc_rsa_signer::{RsaDigestSigner, RsaDigestSignerError};
use tc_sha::{Sha1Digest, Sha224Digest, Sha256Digest, Sha384Digest, Sha512Digest};
use tc_signer::{Signer, SignerInit};

// The key of BC's RsaDigestSignerTest.
const N: &str = "8012a1ed8f41bd483fb6d3c82f6eb231cfec5be750c569296e3d8ae16daf0fdd329625b0c328214da3ba97e27c3a5d171224b520783fee989a0e568ef1ca4c8aef43b491e335788da3d3bb9e98b34a59f440c0ea06f71cb8ed53ef016f599f58cfb28cac5c3c3b858f012d8c694f1e0d55abe080f4735c31228d9f6fad5baaad";
const E: &str = "11";
const D: &str = "f11403a10da8ebd34ac18ea5feee7c99ffdb07591082a7d584379c02b058965513ed741f8d78b728bbb9965f07f563ef313609a687ffdf3d5e391b676cc817996d7789c01edbcf1f4d30401f79d721c8ec2347c3d87632b73694cb2ad665109e89921e108a1ad7a5930ee1f2995949bd6e2777fa59a2ab8dc5c16f87a1ff3f1";
const P: &str = "9f52b724d55be00bff5b3b441b45c19185060777cdcb41ab3cf028f75ae8b6ed2050f39e6c030aa0252101fd5f5e17ed43cba2408386e01aefa3a70d76f53a21";
const Q: &str = "cdc97c3efd74d2790376de49c4b33ed5b1c7fb522e2d101c5b64ba1b528b3797764bf91526daee5573c04386287996f36f5b4683714e10f2e1db35222856d70d";
const DP: &str = "257cdfcc6e6ff87b4b24866a60c51e7c97c52eef033ee24668b0fa948ddc6746da6d667fa0f1a825ae621e95f8525ffb977b353c5b2ecb51a1cc274e7657d171";
const DQ: &str = "60d749870ddc9f4801a1598c205459cdf94f0cdb610625b2fdd50c4917c90b1a198d29ebd60cac6472b4d47b5e5756183467303ddaf78f815b39fae2e5ce8351";
const QINV: &str = "2edd20ef0aec36c431b83741f2afeb1fc7d215e0573062ed088a9f39e7358fb14422e600fc00a24438179076b45a037b9cb5d28c7a32eb7d300b94e8abcbef52";

// The message of BC's RsaDigestSignerTest.
const MESSAGE: &[u8] = &[1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23];

// The signature of MESSAGE under SHA-256, computed apart as m^d mod n of RFC 8017 §9.2,
// with the SHA-256 DigestInfo prefix of its note 1.
const SHA256_SIGNATURE: &str = "3b35bce6174cb3dacfc9eb77c70cffbd68a85699e785f7da1336204193bed8e1af34bfc6e6b24e8e6cfba7c6d6d0618ffe10ee37aee0e6ac50108373529b2631df6220d06c9d7e685d1a7b1623cd6a7eb9fffc9b9438b5def7780fb22d9df8cc872e7885328931be9a5d0fcbe60b619dedaaeaa9329693f5c72318dc77e10579";

fn int(hex: &str) -> PaddedBigUint {
    PaddedBigUint::from_str_radix(hex, 16).unwrap()
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn public_key() -> RsaKey {
    RsaKeyOwned::new(false, int(N), int(E)).into()
}

fn private_key() -> RsaKey {
    RsaPrivateCrtKeyOwned::new(
        int(N),
        int(E),
        int(D),
        int(P),
        int(Q),
        int(DP),
        int(DQ),
        int(QINV),
    )
    .into()
}

fn sha256() -> AlgorithmIdentifier {
    AlgorithmIdentifier::with_null(Pkcs1Algorithm::SHA256.oid())
}

fn sign<H: Digest>(digest: H, algorithm: AlgorithmIdentifier, message: &[u8]) -> Vec<u8> {
    let mut signer = RsaDigestSigner::new(RsaEngine::new(), digest, algorithm);
    signer.init(&private_key()).unwrap();
    signer.update(message).unwrap();
    let mut signature = vec![0; signer.max_signature_size()];
    let len = signer.generate_signature(&mut signature).unwrap();
    signature.truncate(len);
    signature
}

fn verify<H: Digest>(
    digest: H,
    algorithm: AlgorithmIdentifier,
    message: &[u8],
    signature: &[u8],
) -> bool {
    let mut signer = RsaDigestSigner::new(RsaEngine::new(), digest, algorithm);
    signer.init(&public_key()).unwrap();
    signer.update(message).unwrap();
    signer.verify_signature(signature).unwrap()
}

#[test]
fn sha_256_signs_as_rfc_8017_computes_apart() {
    let signature = sign(Sha256Digest::new(), sha256(), MESSAGE);
    assert_eq!(signature, bytes(SHA256_SIGNATURE));
    assert!(verify(Sha256Digest::new(), sha256(), MESSAGE, &signature));
}

#[test]
fn each_sha_digest_signs_and_verifies_under_its_own_identifier() {
    fn round_trip<H: Digest>(digest: impl Fn() -> H, algorithm: &AlgorithmIdentifier) {
        let signature = sign(digest(), algorithm.clone(), MESSAGE);
        assert_eq!(signature.len(), 128);
        assert!(verify(digest(), algorithm.clone(), MESSAGE, &signature));
    }
    let with_null = |algorithm: tc_asn1::NamedOid| AlgorithmIdentifier::with_null(algorithm.oid());
    round_trip(Sha1Digest::new, &with_null(Pkcs1Algorithm::SHA1));
    round_trip(Sha224Digest::new, &with_null(Pkcs1Algorithm::SHA224));
    round_trip(Sha256Digest::new, &with_null(Pkcs1Algorithm::SHA256));
    round_trip(Sha384Digest::new, &with_null(Pkcs1Algorithm::SHA384));
    round_trip(Sha512Digest::new, &with_null(Pkcs1Algorithm::SHA512));
}

#[test]
fn absent_and_null_parameters_verify_each_other_as_in_bc() {
    let absent = AlgorithmIdentifier::new(Pkcs1Algorithm::SHA256.oid());
    let signature = sign(Sha256Digest::new(), absent.clone(), MESSAGE);
    assert_ne!(signature, bytes(SHA256_SIGNATURE));
    assert!(verify(Sha256Digest::new(), sha256(), MESSAGE, &signature));
    let signature = bytes(SHA256_SIGNATURE);
    assert!(verify(Sha256Digest::new(), absent, MESSAGE, &signature));
}

#[test]
fn a_loose_digestinfo_over_a_tampered_hash_does_not_verify() {
    let mut hash = [0; 32];
    let mut digest = Sha256Digest::new();
    digest.update(MESSAGE);
    digest.do_final(&mut hash);
    hash[31] ^= 0x01;
    hash[30] ^= 0x80;
    let loose = DigestInfo::new(
        AlgorithmIdentifier::new(Pkcs1Algorithm::SHA256.oid()),
        &hash,
    )
    .encode_to_vec(&EncodingOptions::DER)
    .unwrap();
    let mut encoding = Pkcs1Encoding::<RsaEngine, _>::new(rand::rng());
    encoding
        .init(CipherDirection::Encrypt, &private_key())
        .unwrap();
    let mut forged = [0; 128];
    encoding.process_block(&loose, &mut forged).unwrap();
    assert!(!verify(Sha256Digest::new(), sha256(), MESSAGE, &forged));
}

#[test]
fn another_message_or_a_damaged_signature_does_not_verify() {
    let signature = bytes(SHA256_SIGNATURE);
    assert!(!verify(
        Sha256Digest::new(),
        sha256(),
        b"another message",
        &signature
    ));
    let mut damaged = signature.clone();
    damaged[64] ^= 1;
    assert!(!verify(Sha256Digest::new(), sha256(), MESSAGE, &damaged));
    assert!(!verify(
        Sha256Digest::new(),
        sha256(),
        MESSAGE,
        &signature[1..]
    ));
    assert!(!verify(
        Sha256Digest::new(),
        sha256(),
        MESSAGE,
        &[0xff; 129]
    ));
}

#[test]
fn the_key_decides_whether_the_signer_signs_or_verifies() {
    let mut signer = RsaDigestSigner::new(RsaEngine::new(), Sha256Digest::new(), sha256());
    assert!(matches!(
        signer.update(MESSAGE),
        Err(RsaDigestSignerError::NotInitialized)
    ));
    signer.init(&public_key()).unwrap();
    assert_eq!(signer.max_signature_size(), 128);
    assert!(matches!(
        signer.generate_signature(&mut [0; 128]),
        Err(RsaDigestSignerError::NotForSigning)
    ));
    signer.init(&private_key()).unwrap();
    assert_eq!(signer.max_signature_size(), 128);
    assert!(matches!(
        signer.verify_signature(&[0; 128]),
        Err(RsaDigestSignerError::NotForVerifying)
    ));
}

#[test]
fn each_signature_and_reset_start_a_new_message() {
    let mut signer = RsaDigestSigner::new(RsaEngine::new(), Sha256Digest::new(), sha256());
    signer.init(&private_key()).unwrap();
    let mut signature = [0; 128];
    for _ in 0..2 {
        signer.update(MESSAGE).unwrap();
        signer.generate_signature(&mut signature).unwrap();
        assert_eq!(signature.as_slice(), bytes(SHA256_SIGNATURE));
    }
    signer.update(b"discarded").unwrap();
    signer.reset();
    signer.update(MESSAGE).unwrap();
    signer.generate_signature(&mut signature).unwrap();
    assert_eq!(signature.as_slice(), bytes(SHA256_SIGNATURE));
}

#[test]
fn a_short_output_is_turned_down_by_the_encoding() {
    let mut signer = RsaDigestSigner::new(RsaEngine::new(), Sha256Digest::new(), sha256());
    signer.init(&private_key()).unwrap();
    signer.update(MESSAGE).unwrap();
    assert!(matches!(
        signer.generate_signature(&mut [0; 127]),
        Err(RsaDigestSignerError::Cipher(_))
    ));
}
