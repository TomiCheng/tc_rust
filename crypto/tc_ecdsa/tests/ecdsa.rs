use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use tc_bigint::{U256, U384, U521};
use tc_digest::Digest;
use tc_ecdsa::{
    EcdsaError, HMacKCalculator, KCalculator, SigningKey, VerifyingKey, calculate_e, decode_plain,
    encode_plain, sign_deterministic, sign_randomized, verify,
};
use tc_sha::{Sha256Digest, Sha384Digest, Sha512Digest};

fn u256(value: &str) -> U256 {
    U256::from_str_radix(value, 16).unwrap()
}

fn u384(value: &str) -> U384 {
    U384::from_str_radix(value, 16).unwrap()
}

fn u521(value: &str) -> U521 {
    U521::from_str_radix(value, 16).unwrap()
}

fn hash<D: Digest>(mut digest: D, message: &[u8]) -> Vec<u8> {
    digest.update(message);
    let mut output = vec![0; digest.digest_size()];
    digest.do_final(&mut output);
    output
}

struct SequenceRng(u8);

impl TryRng for SequenceRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        output.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

impl TryCryptoRng for SequenceRng {}

#[test]
fn rfc6979_p256_sha256_vector_matches_k_r_and_s() {
    // RFC 6979 A.2.5，訊息為 "sample"。
    let (curve, generator) = tc_fp_curve::named_curves::secp256r1();
    let d = u256("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let message_hash = hash(Sha256Digest::new(), b"sample");
    let expected_k = u256("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
    let expected_r = u256("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    let expected_s = u256("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");

    let mut calculator = HMacKCalculator::new(Sha256Digest::new());
    calculator.init(curve.order().unwrap(), &d, &message_hash);
    assert_eq!(calculator.next_k(), expected_k);

    let key = SigningKey::new(curve, generator, d).unwrap();
    assert_eq!(
        sign_deterministic(&key, &message_hash, Sha256Digest::new()).unwrap(),
        (expected_r, expected_s)
    );
}

#[test]
fn rfc6979_p384_sha384_vector_matches_k_r_and_s() {
    // RFC 6979 A.2.6，訊息為 "sample"。
    let (curve, generator) = tc_fp_custom::secp384r1();
    let d = u384(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
    );
    let message_hash = hash(Sha384Digest::new(), b"sample");
    let expected_k = u384(
        "94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA2907E3E83BA95368623B8C4686915CF9",
    );
    let expected_r = u384(
        "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46",
    );
    let expected_s = u384(
        "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8",
    );

    let mut calculator = HMacKCalculator::new(Sha384Digest::new());
    calculator.init(curve.order(), &d, &message_hash);
    assert_eq!(calculator.next_k(), expected_k);

    let key = SigningKey::new(curve, generator, d).unwrap();
    assert_eq!(
        sign_deterministic(&key, &message_hash, Sha384Digest::new()).unwrap(),
        (expected_r, expected_s)
    );
}

#[test]
fn rfc6979_p521_sha512_vector_matches_k_r_and_s() {
    // RFC 6979 A.2.7，訊息為 "sample"。
    let (curve, generator) = tc_fp_custom::secp521r1();
    let d = u521(
        "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
    );
    let message_hash = hash(Sha512Digest::new(), b"sample");
    let expected_k = u521(
        "1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3",
    );
    let expected_r = u521(
        "0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA",
    );
    let expected_s = u521(
        "0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A",
    );

    let mut calculator = HMacKCalculator::new(Sha512Digest::new());
    calculator.init(curve.order(), &d, &message_hash);
    assert_eq!(calculator.next_k(), expected_k);

    let key = SigningKey::new(curve, generator, d).unwrap();
    assert_eq!(
        sign_deterministic(&key, &message_hash, Sha512Digest::new()).unwrap(),
        (expected_r, expected_s)
    );
}

#[test]
fn nist_p256_sigver_vector_accepts_valid_and_rejects_mutations() {
    // NIST P-256 ECDSA 範例；輸入是已完成的 SHA-256 雜湊。
    let (curve, generator) = tc_fp_curve::named_curves::secp256r1();
    let q = curve.create_point(
        u256("B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19"),
        u256("3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09"),
    );
    let key = VerifyingKey::new(curve, generator, q).unwrap();
    let message_hash =
        hex_bytes("A41A41A12A799548211C410C65D8133AFDE34D28BDD542E4B680CF2899C8A8C4");
    let r = u256("2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F");
    let s = u256("DC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1");

    assert!(verify(&key, &message_hash, &r, &s));
    assert!(!verify(&key, &message_hash, &(r + U256::from(1_u8)), &s));
    assert!(!verify(&key, &message_hash, &r, &(s + U256::from(1_u8))));

    let mut changed_hash = message_hash;
    changed_hash[0] ^= 1;
    assert!(!verify(&key, &changed_hash, &r, &s));
}

#[test]
fn bitcoin_secp256k1_public_vector_verifies() {
    // Bitcoin Core 收錄的 Wycheproof tcId 2；此層直接使用 DER 內的 r、s。
    let (curve, generator) = tc_fp_custom::secp256k1();
    let q = curve
        .create_point(
            u256("B838FF44E5BC177BF21189D0766082FC9D843226887FC9760371100B7EE20A6F"),
            u256("F0C9D75BFBA7B31A6BCA1974496EEB56DE357071955D83C4B1BADAA0B21832E9"),
        )
        .unwrap();
    let key = VerifyingKey::new(curve, generator, q).unwrap();
    let message_hash = hash(Sha256Digest::new(), b"123400");
    let r = u256("813EF79CCEFA9A56F7BA805F0E478584FE5F0DD5F567BC09B5123CCBC9832365");
    let s = u256("6FF18A52DCC0336F7AF62400A6DD9B810732BAF1FF758000D6F613A556EB31BA");

    assert!(verify(&key, &message_hash, &r, &s));
}

#[test]
fn deterministic_signatures_match_across_p256_backends() {
    let (generic_curve, generic_generator) = tc_fp_curve::named_curves::secp256r1();
    let (custom_curve, custom_generator) = tc_fp_custom::secp256r1();
    let d = u256("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let message_hash = hash(Sha256Digest::new(), b"sample");
    let generic_key = SigningKey::new(generic_curve, generic_generator, d).unwrap();
    let custom_key = SigningKey::new(custom_curve, custom_generator, d).unwrap();

    let first = sign_deterministic(&generic_key, &message_hash, Sha256Digest::new()).unwrap();
    let repeated = sign_deterministic(&generic_key, &message_hash, Sha256Digest::new()).unwrap();
    let specialized = sign_deterministic(&custom_key, &message_hash, Sha256Digest::new()).unwrap();

    assert_eq!(first, repeated);
    assert_eq!(first, specialized);
    assert!(verify(
        &generic_key.verifying_key().unwrap(),
        &message_hash,
        &first.0,
        &first.1
    ));
    assert!(verify(
        &custom_key.verifying_key().unwrap(),
        &message_hash,
        &specialized.0,
        &specialized.1
    ));
}

#[test]
fn randomized_signatures_differ_and_both_verify() {
    let (curve, generator) = tc_fp_curve::named_curves::secp256r1();
    let key = SigningKey::new(curve, generator, U256::from(7_u8)).unwrap();
    let verifying_key = key.verifying_key().unwrap();
    let message_hash = hash(Sha256Digest::new(), b"randomized ECDSA");
    let mut rng = SequenceRng(1);

    let first = sign_randomized(&key, &message_hash, &mut rng).unwrap();
    let second = sign_randomized(&key, &message_hash, &mut rng).unwrap();

    assert_ne!(first, second);
    assert!(verify(&verifying_key, &message_hash, &first.0, &first.1));
    assert!(verify(&verifying_key, &message_hash, &second.0, &second.1));
}

#[test]
fn key_signature_and_plain_encoding_boundaries_are_rejected() {
    let (curve, generator) = tc_fp_curve::named_curves::secp256r1();
    let n = *curve.order().unwrap();
    assert!(matches!(
        SigningKey::new(curve.clone(), generator.clone(), U256::zero()),
        Err(EcdsaError::InvalidPrivateKey)
    ));
    assert!(matches!(
        SigningKey::new(curve.clone(), generator.clone(), n),
        Err(EcdsaError::InvalidPrivateKey)
    ));
    assert!(matches!(
        VerifyingKey::new(curve.clone(), generator.clone(), curve.infinity()),
        Err(EcdsaError::InvalidPublicKey)
    ));

    let key = SigningKey::new(curve, generator, U256::from(3_u8)).unwrap();
    let verifying_key = key.verifying_key().unwrap();
    let message_hash = hash(Sha256Digest::new(), b"boundaries");
    let zero = U256::zero();
    let one = U256::from(1_u8);
    assert!(!verify(&verifying_key, &message_hash, &zero, &one));
    assert!(!verify(&verifying_key, &message_hash, &one, &zero));
    assert!(!verify(&verifying_key, &message_hash, &n, &one));
    assert!(!verify(&verifying_key, &message_hash, &one, &n));

    let encoded = encode_plain(&n, &one, &(n - one));
    assert_eq!(decode_plain(&n, &encoded), Ok((one, n - one)));
    assert_eq!(
        decode_plain(&n, &encoded[..encoded.len() - 1]),
        Err(EcdsaError::InvalidEncodingLength)
    );
    assert_eq!(
        decode_plain(&n, &encode_plain(&n, &zero, &one)),
        Err(EcdsaError::InvalidSignatureValue)
    );
    assert_eq!(
        decode_plain(&n, &encode_plain(&n, &one, &n)),
        Err(EcdsaError::InvalidSignatureValue)
    );
}

#[test]
fn calculate_e_handles_p521_short_hashes_and_non_byte_aligned_truncation() {
    let (curve, _) = tc_fp_custom::secp521r1();
    let n = curve.order();
    let sha256 = hash(Sha256Digest::new(), b"P-521 with SHA-256");
    let sha512 = hash(Sha512Digest::new(), b"P-521 with SHA-512");

    assert_eq!(
        calculate_e(n, &sha256),
        Ok(U521::from_be_bytes(&sha256).unwrap())
    );
    assert_eq!(
        calculate_e(n, &sha512),
        Ok(U521::from_be_bytes(&sha512).unwrap())
    );

    let oversized = [0xa5_u8; 66];
    let expected = U521::from_be_bytes(&oversized).unwrap() >> 7;
    assert_eq!(calculate_e(n, &oversized), Ok(expected));
    assert_eq!(expected.bit_length(), 521);
}

#[test]
fn rfc6979_binary_sect233k1_vector_signs_and_verifies() {
    // RFC 6979 A.2.9，訊息為 "sample"，涵蓋 F2m 的 SecretCurve 路徑。
    let (curve, generator) = tc_f2m_custom::sect233k1();
    let d = u256("103B2142BDC2A3C3B55080D09DF1808F79336DA2399F5CA7171D1BE9B0");
    let message_hash = hash(Sha256Digest::new(), b"sample");
    let expected_k = u256("73552F9CAC5774F74F485FA253871F2109A0C86040552EAA67DBA92DC9");
    let expected_r = u256("38AD9C1D2CB29906E7D63C24601AC55736B438FB14F4093D6C32F63A10");
    let expected_s = u256("647AAD2599C21B6EE89BE7FF957D98F684B7921DE1FD3CC82C079624F4");

    let mut calculator = HMacKCalculator::new(Sha256Digest::new());
    calculator.init(curve.order().unwrap(), &d, &message_hash);
    assert_eq!(calculator.next_k(), expected_k);

    let key = SigningKey::new(curve, generator, d).unwrap();
    let signature = sign_deterministic(&key, &message_hash, Sha256Digest::new()).unwrap();
    assert_eq!(signature, (expected_r, expected_s));
    assert!(verify(
        &key.verifying_key().unwrap(),
        &message_hash,
        &signature.0,
        &signature.1
    ));
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn hex_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
