//! `Sm2Engine`：Bouncy Castle `SM2EngineTest` 的向量（SM2 草案的 Fp 測試曲線兩種排列，
//! 以及餘因子為 4 的 F2m 測試曲線），sm2p256v1 上的來回與錯誤。

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};
use tc_asym_cipher::{
    AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator, KeyPairGeneratorInit,
};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};
use tc_f2m_curve::{F2mCtCurve, F2mField};
use tc_fp_curve::{FpCtCurve, FpField};
use tc_fp_custom::named_curves::SM2P256V1;
use tc_fp_custom::{SM2P256V1FieldElement, SecPCtCurve};
use tc_sm2::{Sm2Curve, Sm2Engine, Sm2Error, Sm2Mode};

fn bytes(hex: &str) -> Vec<u8> {
    let hex: String = hex.split_whitespace().collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn integer(hex: &str) -> PaddedBigUint {
    PaddedBigUint::from_be(&bytes(hex)).unwrap()
}

/// BC 的 `TestRandomBigInteger`：吐出固定的位元組。`random_bits` 由低位元組讀起，所以
/// 給出 k 的小端序位元組，就會抽到 k。
struct FixedRng(Vec<u8>);

impl FixedRng {
    fn for_value(hex: &str) -> Self {
        let mut value = bytes(hex);
        value.reverse();
        Self(value)
    }
}

impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut word = [0; 4];
        self.try_fill_bytes(&mut word)?;
        Ok(u32::from_le_bytes(word))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut word = [0; 8];
        self.try_fill_bytes(&mut word)?;
        Ok(u64::from_le_bytes(word))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Infallible> {
        let taken: Vec<u8> = self.0.drain(..output.len()).collect();
        output.copy_from_slice(&taken);
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

/// 以固定的 d 與 k 加密 "encryption standard"，比對 BC 的密文，再解密回來。
fn known_answer<C: Sm2Curve>(g: C::Point, d: &str, k: &str, mode: Sm2Mode, expected: &str) {
    let d = integer(d);
    let q = C::multiply(&g, &d);
    let public_key = EcPublicKey::<C>::new(g.clone(), &q).unwrap();
    let private_key = EcPrivateKey::<C>::new(g, d).unwrap();
    let message = b"encryption standard";

    let mut encryptor = Sm2Engine::new(mode, FixedRng::for_value(k));
    encryptor
        .init(CipherDirection::Encrypt, &public_key)
        .unwrap();
    let mut ciphertext = vec![0; encryptor.output_size(message.len())];
    let length = encryptor.process_block(message, &mut ciphertext).unwrap();
    assert_eq!(ciphertext[..length], bytes(expected)[..]);

    let mut decryptor = Sm2Engine::new(mode, FixedRng(Vec::new()));
    decryptor
        .init(CipherDirection::Decrypt, &private_key)
        .unwrap();
    let mut plaintext = vec![0; decryptor.output_size(length)];
    let written = decryptor
        .process_block(&ciphertext[..length], &mut plaintext)
        .unwrap();
    assert_eq!(&plaintext[..written], message);
}

const FP_D: &str = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
const FP_K: &str = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";

fn fp_test_field() -> FpField {
    FpField::new(integer(
        "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
    ))
    .unwrap()
}

fn fp_test_curve(field: &FpField) -> FpCtCurve<'_> {
    FpCtCurve::new(
        field,
        &integer("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"),
        &integer("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"),
        Some(integer(
            "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
        )),
        Some(PaddedBigUint::from(1u8)),
    )
    .unwrap()
}

#[test]
fn the_fp_test_curve_matches_bouncy_castle_in_c1c2c3_order() {
    let field = fp_test_field();
    let curve = fp_test_curve(&field);
    let g = curve
        .create_point(
            &integer("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"),
            &integer("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"),
        )
        .unwrap();
    known_answer::<&FpCtCurve<'_>>(
        g,
        FP_D,
        FP_K,
        Sm2Mode::C1C2C3,
        "04245C26 FB68B1DD DDB12C4B 6BF9F2B6 D5FE60A3 83B0D18D 1C4144AB F17F6252\
         E776CB92 64C2A7E8 8E52B199 03FDC473 78F605E3 6811F5C0 7423A24B 84400F01\
         B8650053 A89B41C4 18B0C3AA D00D886C 00286467 9C3D7360 C30156FA B7C80A02\
         76712DA9 D8094A63 4B766D3A 285E0748 0653426D",
    );
}

#[test]
fn the_fp_test_curve_matches_bouncy_castle_in_c1c3c2_order() {
    let field = fp_test_field();
    let curve = fp_test_curve(&field);
    let g = curve
        .create_point(
            &integer("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"),
            &integer("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"),
        )
        .unwrap();
    known_answer::<&FpCtCurve<'_>>(
        g,
        FP_D,
        FP_K,
        Sm2Mode::C1C3C2,
        "04245C26 FB68B1DD DDB12C4B 6BF9F2B6 D5FE60A3 83B0D18D 1C4144AB F17F6252\
         E776CB92 64C2A7E8 8E52B199 03FDC473 78F605E3 6811F5C0 7423A24B 84400F01\
         B8 9C3D7360 C30156FA B7C80A02\
         76712DA9 D8094A63 4B766D3A 285E0748 0653426D 650053 A89B41C4 18B0C3AA D00D886C 00286467",
    );
}

#[test]
fn the_f2m_test_curve_with_cofactor_four_matches_bouncy_castle() {
    let field = F2mField::trinomial(257, 12).unwrap();
    let curve = F2mCtCurve::new(
        field,
        &[0; 33],
        &bytes("00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B"),
        Some(integer(
            "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D",
        )),
        Some(PaddedBigUint::from(4u8)),
    )
    .unwrap();
    let g = curve
        .create_point(
            &bytes("00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD"),
            &bytes("013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E"),
        )
        .unwrap();
    known_answer::<&F2mCtCurve>(
        g,
        "56A270D17377AA9A367CFA82E46FA5267713A9B91101D0777B07FCE018C757EB",
        "6D3B497153E3E92524E5C122682DBDC8705062E20B917A5F8FCDB8EE4C66663D",
        Sm2Mode::C1C2C3,
        "04019D23 6DDB3050 09AD52C5 1BB93270 9BD534D4 76FBB7B0 DF9542A8 A4D890A3\
         F2E100B2 3B938DC0 A94D1DF8 F42CF45D 2D6601BF 638C3D7D E75A29F0 2AFB7E45\
         E91771FD 55AC6213 C2A8A040 E4CAB5B2 6A9CFCDA 737373A4 8625D375 8FA37B3E\
         AB80E9CF CABA665E 3199EA15 A1FA8189 D96F5791 25E4",
    );
}

type Sm2P256 = SecPCtCurve<SM2P256V1FieldElement>;

fn sm2p256v1_keys(curve: &Sm2P256) -> (EcPublicKey<&Sm2P256>, EcPrivateKey<&Sm2P256>) {
    let g = SM2P256V1.ct_generator(curve);
    let mut rng = rand::rng();
    let mut generator = EcKeyPairGenerator::<&Sm2P256>::new();
    generator
        .init(EcKeyGenerationParams::new(g, &mut rng))
        .unwrap();
    generator.generate_key_pair().unwrap()
}

#[test]
fn messages_of_every_length_round_trip_on_sm2p256v1_in_both_orders() {
    let curve = SM2P256V1.ct_curve();
    let (public_key, private_key) = sm2p256v1_keys(&curve);
    for mode in [Sm2Mode::C1C2C3, Sm2Mode::C1C3C2] {
        for length in [1, 31, 32, 33, 64, 100] {
            let message: Vec<u8> = (0..length).map(|i| i as u8).collect();
            let mut encryptor = Sm2Engine::new(mode, rand::rng());
            encryptor
                .init(CipherDirection::Encrypt, &public_key)
                .unwrap();
            let mut ciphertext = vec![0; encryptor.output_size(length)];
            assert_eq!(ciphertext.len(), 1 + 64 + length + 32);
            encryptor.process_block(&message, &mut ciphertext).unwrap();

            let mut decryptor = Sm2Engine::new(mode, rand::rng());
            decryptor
                .init(CipherDirection::Decrypt, &private_key)
                .unwrap();
            let mut plaintext = vec![0; decryptor.output_size(ciphertext.len())];
            assert_eq!(plaintext.len(), length);
            decryptor
                .process_block(&ciphertext, &mut plaintext)
                .unwrap();
            assert_eq!(plaintext, message, "{mode:?}, {length} bytes");
        }
    }
}

#[test]
fn a_tampered_ciphertext_is_rejected_and_its_output_wiped() {
    let curve = SM2P256V1.ct_curve();
    let (public_key, private_key) = sm2p256v1_keys(&curve);
    let mut encryptor = Sm2Engine::new(Sm2Mode::C1C3C2, rand::rng());
    encryptor
        .init(CipherDirection::Encrypt, &public_key)
        .unwrap();
    let mut ciphertext = vec![0; encryptor.output_size(16)];
    encryptor
        .process_block(&[0x5a; 16], &mut ciphertext)
        .unwrap();

    let mut decryptor = Sm2Engine::new(Sm2Mode::C1C3C2, rand::rng());
    decryptor
        .init(CipherDirection::Decrypt, &private_key)
        .unwrap();
    // 改 C3、改 C2：核對不過，輸出清為 0。
    for index in [65, ciphertext.len() - 1] {
        let mut tampered = ciphertext.clone();
        tampered[index] ^= 1;
        let mut plaintext = vec![0xff; 16];
        assert_eq!(
            decryptor.process_block(&tampered, &mut plaintext),
            Err(Sm2Error::InvalidCiphertext)
        );
        assert_eq!(plaintext, vec![0; 16]);
    }
    // 改 C1：不再是曲線上的點。
    let mut tampered = ciphertext.clone();
    tampered[10] ^= 1;
    assert_eq!(
        decryptor.process_block(&tampered, &mut [0; 16]),
        Err(Sm2Error::InvalidPoint)
    );
    // 太短，放不下 C1 與 C3。
    assert_eq!(
        decryptor.process_block(&ciphertext[..96], &mut [0; 16]),
        Err(Sm2Error::CiphertextTooShort)
    );
}

#[test]
fn misuse_is_reported() {
    let curve = SM2P256V1.ct_curve();
    let (public_key, private_key) = sm2p256v1_keys(&curve);
    let mut engine = Sm2Engine::new(Sm2Mode::C1C2C3, rand::rng());
    assert_eq!(engine.output_size(10), 0);
    assert_eq!(
        engine.process_block(b"x", &mut [0; 128]),
        Err(Sm2Error::NotInitialized)
    );
    assert_eq!(
        engine.init(CipherDirection::Decrypt, &public_key),
        Err(Sm2Error::WrongKeyForDirection)
    );
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &private_key),
        Err(Sm2Error::WrongKeyForDirection)
    );
    engine.init(CipherDirection::Encrypt, &public_key).unwrap();
    assert_eq!(
        engine.process_block(&[], &mut [0; 128]),
        Err(Sm2Error::EmptyInput)
    );
    assert_eq!(
        engine.process_block(b"x", &mut [0; 97]),
        Err(Sm2Error::OutputTooShort)
    );
}

#[test]
fn another_digest_changes_the_tag_length() {
    let curve = SM2P256V1.ct_curve();
    let (public_key, private_key) = sm2p256v1_keys(&curve);
    let mut encryptor =
        Sm2Engine::with_digest(tc_sha::Sha512Digest::new(), Sm2Mode::C1C2C3, rand::rng());
    encryptor
        .init(CipherDirection::Encrypt, &public_key)
        .unwrap();
    let mut ciphertext = vec![0; encryptor.output_size(3)];
    assert_eq!(ciphertext.len(), 1 + 64 + 3 + 64);
    encryptor.process_block(b"abc", &mut ciphertext).unwrap();

    let mut decryptor =
        Sm2Engine::with_digest(tc_sha::Sha512Digest::new(), Sm2Mode::C1C2C3, rand::rng());
    decryptor
        .init(CipherDirection::Decrypt, &private_key)
        .unwrap();
    let mut plaintext = [0; 3];
    decryptor
        .process_block(&ciphertext, &mut plaintext)
        .unwrap();
    assert_eq!(&plaintext, b"abc");
}
