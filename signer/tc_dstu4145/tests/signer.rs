//! `Dstu4145Signer`：Bouncy Castle `DSTU4145Test` 的五組向量（163、173、283、431 位元與雜湊
//! 截斷），以固定的亂數抽出 BC 的 e；經 `DsaDigestSigner` 接上 `tc_signer`；公鑰為 −d·G 的
//! 金鑰產生器；以及錯誤。

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_dsa::{Dsa, DsaDigestSigner, DsaInit, PlainDsaEncoding, RandomDsaKCalculator};
use tc_dstu4145::{Dstu4145Error, Dstu4145KeyPairGenerator, Dstu4145Signer};
use tc_ec_core::{Curve, Point};
use tc_ec_key::{EcKeyGenerationParams, EcPrivateKey, EcPublicKey};
use tc_f2m_curve::{F2mCtCurve, F2mField};
use tc_sha::Sha256Digest;
use tc_signer::{Signer, SignerInit};

type Ct<'a> = &'a F2mCtCurve;

fn bytes(hex: &str) -> Vec<u8> {
    let hex = format!("{}{hex}", "0".repeat(hex.len() % 2));
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// 補成 `length` 位元組的大端序。
fn padded(hex: &str, length: usize) -> Vec<u8> {
    let bytes = bytes(hex);
    [vec![0; length - bytes.len()], bytes].concat()
}

fn integer(hex: &str) -> PaddedBigUint {
    let Ok(value) = PaddedBigUint::from_be(&bytes(hex));
    value
}

/// BC 的 `TestRandomData`：依序吐出固定的位元組，BC 一次抽樣取前 ⌈n 的位元數 / 8⌉ 個當
/// 大端序的 e。`random_bits` 由低位元組讀起，所以把這段倒過來給，就會抽到同一個 e。
struct FixedRng(Vec<u8>);

impl FixedRng {
    fn for_draw(hex: &str, n: &PaddedBigUint) -> Self {
        let mut value = bytes(hex);
        value.truncate((n.bits() as usize).div_ceil(8));
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

/// BC 測試的一組參數：域 x^m + x^k3 + x^k2 + x^k1 + 1、a、b、G、n、d。
struct Domain {
    field: (u32, u32, u32, u32),
    a: u8,
    b: &'static str,
    gx: &'static str,
    gy: &'static str,
    n: &'static str,
    d: &'static str,
}

fn curve(domain: &Domain) -> F2mCtCurve {
    let (m, k1, k2, k3) = domain.field;
    let length = (m as usize).div_ceil(8);
    let mut a = vec![0; length];
    a[length - 1] = domain.a;
    F2mCtCurve::new(
        F2mField::pentanomial(m, k1, k2, k3).unwrap(),
        &a,
        &padded(domain.b, length),
        Some(integer(domain.n)),
        Some(PaddedBigUint::from(1u8)),
    )
    .unwrap()
}

/// 公鑰是 −d·G，同 BC 的測試。
fn keys<'a>(curve: Ct<'a>, domain: &Domain) -> (EcPrivateKey<Ct<'a>>, EcPublicKey<Ct<'a>>) {
    let length = curve.field_element_encoding_length();
    let g = curve
        .create_point(&padded(domain.gx, length), &padded(domain.gy, length))
        .unwrap();
    let d = integer(domain.d);
    let q = <Ct<'a>>::multiply(&g, &d).negate();
    (
        EcPrivateKey::new(g.clone(), d).unwrap(),
        EcPublicKey::new(g, &q).unwrap(),
    )
}

/// BC 的步驟：以固定的 e 簽章比對 (r, s)，再以公鑰驗證。
fn known_answer(domain: &Domain, e: &str, hash: &[u8], r: &str, s: &str) {
    let curve = curve(domain);
    let (private_key, public_key) = keys(&curve, domain);
    let rng = FixedRng::for_draw(e, &integer(domain.n));
    let mut signer = Dstu4145Signer::new(RandomDsaKCalculator::new(rng));
    signer.init(&private_key).unwrap();
    let signature = signer.generate_signature(hash).unwrap();
    assert_eq!(signature, (integer(r), integer(s)));

    let mut verifier = Dstu4145Signer::new(RandomDsaKCalculator::new(rand::rng()));
    verifier.init(&public_key).unwrap();
    assert!(
        verifier
            .verify_signature(hash, &signature.0, &signature.1)
            .unwrap()
    );
    assert!(
        !verifier
            .verify_signature(hash, &signature.1, &signature.0)
            .unwrap()
    );
}

/// BC 測試先把雜湊倒過來。
fn reversed(hex: &str) -> Vec<u8> {
    let mut hash = bytes(hex);
    hash.reverse();
    hash
}

const DOMAIN_163: Domain = Domain {
    field: (163, 3, 6, 7),
    a: 1,
    b: "5FF6108462A2DC8210AB403925E638A19C1455D21",
    gx: "72d867f93a93ac27df9ff01affe74885c8c540420",
    gy: "0224a9c3947852b97c5599d5f4ab81122adc3fd9b",
    n: "400000000000000000002BEC12BE2262D39BCF14D",
    d: "183f60fdf7951ff47d67193f8d073790c1c9b5a3e",
};

const DOMAIN_173: Domain = Domain {
    field: (173, 1, 2, 10),
    a: 0,
    b: "108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9",
    gx: "BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9",
    gy: "D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C",
    n: "800000000000000000000189B4E67606E3825BB2831",
    d: "955CD7E344303D1034E66933DC21C8044D42ADB8",
};

#[test]
fn the_163_bit_vector_matches_bouncy_castle() {
    known_answer(
        &DOMAIN_163,
        "01025e40bd97db012b7a1d79de8e12932d247f61c6",
        &reversed("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff"),
        "274ea2c0caa014a0d80a424f59ade7a93068d08a7",
        "2100d86957331832b8e8c230f5bd6a332b3615aca",
    );
}

#[test]
fn the_173_bit_vector_matches_bouncy_castle() {
    known_answer(
        &DOMAIN_173,
        "0000137449348C1249971759D99C252FFE1E14D8B31F",
        &reversed("0137187EA862117EF1484289470ECAC802C5A651FDA8"),
        "13ae89746386709cdbd237cc5ec20ca30004a82ead8",
        "3597912cdd093b3e711ccb74a79d3c4ab4c7cccdc60",
    );
}

#[test]
fn the_283_bit_vector_matches_bouncy_castle() {
    known_answer(
        &Domain {
            field: (283, 5, 7, 12),
            a: 1,
            b: "27B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5",
            gx: "4D95820ACE761110824CE425C8089129487389B7F0E0A9D043DDC0BB0A4CC9EB25",
            gy: "954C9C4029B2C62DE35C2B9C2A164984BF1101951E3A68ED03DF234DDE5BB2013152F2",
            n: "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307",
            d: "B844EEAF15213E4BAD4FB84796D68F2448DB8EB7B4621EC0D51929874892C43E",
        },
        "00000000245383CB3AD41BF30F5F7E8FBA858509B2D5558C92D539A6D994BFA98BC6940E",
        &reversed("0137187EA862117EF1484289470ECAC802C5A651FDA8"),
        "12a5edcc38d92208ff23036d75b000c7e4bc0f9af2d40b35f15d6fd15e01234e67781a8",
        "2de0775577f75b643cf5afc80d4fe10b21100690f17e2cab7bdc9b50ec87c5727aeb515",
    );
}

#[test]
fn the_431_bit_vector_matches_bouncy_castle() {
    known_answer(
        &Domain {
            field: (431, 1, 3, 5),
            a: 1,
            b: "3CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3",
            gx: "9548BCDF314CEEEAF099C780FFEFBF93F9FE5B5F55547603C9C8FC1A2774170882B3BE35E892C6D4296B8DEA282EC30FB344272791",
            gy: "4C6CBD7C62A8EEEFDE17A8B5E196E49A22CE6DE128ABD9FBD81FA4411AD5A38E2A810BEDE09A7C6226BCDCB4A4A5DA37B4725E00AA74",
            n: "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF",
            d: "D0F97354E314191FD773E2404F478C8AEE0FF5109F39E6F37D1FEEC8B2ED1691D84C9882CC729E716A71CC013F66CAC60E29E22C",
        },
        "0000C4224DBBD800988DBAA39DE838294C345CDA5F5929D1174AA8D9340A5E79D10ACADE6B53CF873E7301A3871C2073AD75AB530457",
        &reversed("0137187EA862117EF1484289470ECAC802C5A651FDA8"),
        "1911fefb1f494bebcf8dffdf5276946ff9c9f662192ee18c718db47310a439c784fe07577b16e1edbe16179876e0792a634f1c9c3a2e",
        "3852170ee801c2083c52f1ea77b987a5432acecd9c654f064e87bf179e0a397151edbca430082e43bd38a67b55424b5bbc7f2713f620",
    );
}

#[test]
fn a_hash_longer_than_the_field_is_truncated_as_bouncy_castle_does() {
    known_answer(
        &DOMAIN_173,
        "0000C4224DBBD800988DBAA39DE838294C345CDA5F5929D1174AA8D9340A5E79D10ACADE6B53CF873E7301A3871C2073AD75AB530457",
        &bytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        "6bb5c0cb82e5067485458ebfe81025f03b687c63a27",
        "34d6b1868969b86ecf934167c8fe352c63d1074bd",
    );
}

fn padded_integer(value: &PaddedBigUint, length: usize) -> Vec<u8> {
    let bytes = ArrayEncoding::<u8>::to_be(value);
    let start = bytes.len() - length;
    bytes[start..].to_vec()
}

#[test]
fn the_digest_signer_signs_the_hash_the_dsa_would_and_verifies() {
    let curve = curve(&DOMAIN_163);
    let (private_key, public_key) = keys(&curve, &DOMAIN_163);
    let e = "01025e40bd97db012b7a1d79de8e12932d247f61c6";
    let message = b"signed through DsaDigestSigner";

    let mut signer = DsaDigestSigner::with_encoding(
        Dstu4145Signer::new(RandomDsaKCalculator::new(FixedRng::for_draw(
            e,
            &integer(DOMAIN_163.n),
        ))),
        Sha256Digest::new(),
        PlainDsaEncoding,
    );
    signer.init(&private_key).unwrap();
    signer.update(message).unwrap();
    let mut signature = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut signature).unwrap();
    assert_eq!(length, 42);

    // 同一個 e 直接簽 SHA-256(message)，得到同一對 (r, s)。
    let mut hash = vec![0; 32];
    let mut digest = Sha256Digest::new();
    digest.update(message);
    digest.do_final(&mut hash);
    let mut dsa = Dstu4145Signer::new(RandomDsaKCalculator::new(FixedRng::for_draw(
        e,
        &integer(DOMAIN_163.n),
    )));
    dsa.init(&private_key).unwrap();
    let (r, s) = dsa.generate_signature(&hash).unwrap();
    let expected = [padded_integer(&r, 21), padded_integer(&s, 21)].concat();
    assert_eq!(signature[..length], expected[..]);

    let mut verifier = DsaDigestSigner::with_encoding(
        Dstu4145Signer::new(RandomDsaKCalculator::new(rand::rng())),
        Sha256Digest::new(),
        PlainDsaEncoding,
    );
    verifier.init(&public_key).unwrap();
    verifier.update(message).unwrap();
    assert!(verifier.verify_signature(&signature[..length]).unwrap());
    verifier.update(b"another message").unwrap();
    assert!(!verifier.verify_signature(&signature[..length]).unwrap());
}

#[test]
fn the_key_pair_generator_negates_the_public_point() {
    let curve = curve(&DOMAIN_163);
    let (g_key, _) = keys(&curve, &DOMAIN_163);
    let g = g_key.g().clone();
    let mut rng = rand::rng();
    let mut generator = Dstu4145KeyPairGenerator::<Ct<'_>>::new();
    generator
        .init(EcKeyGenerationParams::new(g.clone(), &mut rng))
        .unwrap();
    let (public_key, private_key) = generator.generate_key_pair().unwrap();
    let expected = <Ct<'_>>::multiply(&g, private_key.d()).negate();
    assert!(*public_key.q() == expected.normalize());

    let mut signer = Dstu4145Signer::new(RandomDsaKCalculator::new(rand::rng()));
    signer.init(&private_key).unwrap();
    let (r, s) = signer.generate_signature(b"hash").unwrap();
    let mut verifier = Dstu4145Signer::new(RandomDsaKCalculator::new(rand::rng()));
    verifier.init(&public_key).unwrap();
    assert!(verifier.verify_signature(b"hash", &r, &s).unwrap());
}

#[test]
fn errors_are_reported() {
    let curve = curve(&DOMAIN_163);
    let (private_key, public_key) = keys(&curve, &DOMAIN_163);
    let mut signer = Dstu4145Signer::<Ct<'_>, _>::new(RandomDsaKCalculator::new(rand::rng()));
    assert_eq!(
        signer.generate_signature(b"hash"),
        Err(Dstu4145Error::NotInitialized)
    );
    signer.init(&public_key).unwrap();
    assert_eq!(
        signer.generate_signature(b"hash"),
        Err(Dstu4145Error::NotForSigning)
    );
    signer.init(&private_key).unwrap();
    let one = PaddedBigUint::from(1u8);
    assert_eq!(
        signer.verify_signature(b"hash", &one, &one),
        Err(Dstu4145Error::NotForVerifying)
    );

    let mut verifier = Dstu4145Signer::new(RandomDsaKCalculator::new(rand::rng()));
    verifier.init(&public_key).unwrap();
    let zero = PaddedBigUint::from(0u8);
    let n = integer(DOMAIN_163.n);
    for (r, s) in [(&zero, &one), (&one, &zero), (&n, &one), (&one, &n)] {
        assert!(!verifier.verify_signature(b"hash", r, s).unwrap());
    }
}
