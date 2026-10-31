//! `Sm2Signer`：Bouncy Castle `SM2SignerTest` 的七組向量（SM2 草案的 Fp 曲線、sm2p256v1、
//! P-256，各以 SM3 與 SHA-256；餘因子為 4 的 F2m 曲線），同一個簽章器連簽三次再驗證，
//! r 與 s 的範圍，以及錯誤。

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_dsa::{DsaKCalculator, PlainDsaEncoding, RandomDsaKCalculator};
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_f2m_curve::{F2mCtCurve, F2mField};
use tc_fp_curve::named_curves::SECP256R1;
use tc_fp_curve::{FpCtCurve, FpField};
use tc_fp_custom::named_curves::SM2P256V1;
use tc_fp_custom::{SM2P256V1FieldElement, SecPCtCurve};
use tc_sha::Sha256Digest;
use tc_signer::{Signer, SignerInit};
use tc_sm2::{Sm2Curve, Sm2Error, Sm2Signer, Sm2SignerParams};
use tc_sm3::Sm3Digest;

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

/// BC 測試以 `TestRandomBigInteger` 固定的 k。
struct FixedK(PaddedBigUint);

impl DsaKCalculator<PaddedBigUint> for FixedK {
    fn init(&mut self, _: &PaddedBigUint, _: &PaddedBigUint, _: &[u8]) {}

    fn next_k(&mut self) -> PaddedBigUint {
        self.0.clone()
    }
}

/// 一組向量：私鑰 `x`、固定的 `nonce`，預期的 r 與 s。
struct Vector {
    id: &'static str,
    message: &'static str,
    x: &'static str,
    nonce: &'static str,
    r: &'static str,
    s: &'static str,
}

fn check<C: Sm2Curve, D: Digest + Clone>(g: &C::Point, digest: impl Fn() -> D, vector: &Vector) {
    let d = integer(vector.x);
    let private_key = EcPrivateKey::<C>::new(g.clone(), d.clone()).unwrap();
    let public_key = EcPublicKey::<C>::new(g.clone(), &C::multiply(g, &d)).unwrap();
    let id = vector.id.as_bytes().to_vec();

    let mut signer = Sm2Signer::<C, _, _>::with_digest(FixedK(integer(vector.nonce)), digest())
        .with_encoding(PlainDsaEncoding);
    signer
        .init(&Sm2SignerParams::new(private_key).with_user_id(id.clone()))
        .unwrap();
    signer.update(vector.message.as_bytes()).unwrap();
    let mut signature = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut signature).unwrap();
    let half = length / 2;
    assert_eq!(signature[..half], bytes(vector.r)[..], "r of {}", vector.id);
    assert_eq!(
        signature[half..length],
        bytes(vector.s)[..],
        "s of {}",
        vector.id
    );

    let mut verifier = Sm2Signer::<C, _, _>::with_digest(FixedK(integer("01")), digest())
        .with_encoding(PlainDsaEncoding);
    verifier
        .init(&Sm2SignerParams::new(public_key).with_user_id(id))
        .unwrap();
    verifier.update(vector.message.as_bytes()).unwrap();
    assert!(verifier.verify_signature(&signature[..length]).unwrap());
}

const DRAFT_KEY: &str = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
const DRAFT_NONCE: &str = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
const STANDARD_KEY: &str = "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC";
const STANDARD_NONCE: &str = "3174C6FFC3C279D2422F3FC0A9F3E574674A4490FE45A5325CAF7D3EC4C8F96C";

#[test]
fn the_draft_fp_curve_matches_bouncy_castle_with_sm3_and_sha256() {
    let field = FpField::new(integer(
        "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
    ))
    .unwrap();
    let curve = FpCtCurve::new(
        &field,
        &integer("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"),
        &integer("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"),
        Some(integer(
            "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
        )),
        Some(PaddedBigUint::from(1u8)),
    )
    .unwrap();
    let g = curve
        .create_point(
            &integer("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"),
            &integer("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"),
        )
        .unwrap();
    let vector = |r, s| Vector {
        id: "ALICE123@YAHOO.COM",
        message: "message digest",
        x: DRAFT_KEY,
        nonce: DRAFT_NONCE,
        r,
        s,
    };
    check::<&FpCtCurve<'_>, _>(
        &g,
        Sm3Digest::new,
        &vector(
            "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1",
            "6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7",
        ),
    );
    check::<&FpCtCurve<'_>, _>(
        &g,
        Sha256Digest::new,
        &vector(
            "7D62A5EDBDDC8AF4D69C9E37A60D31F5CEFE8727709117E0869648D0A9AE4F57",
            "1E5E89718B716AAFC6253443168E4F7CF7E1B7B3934307686CE5947C1BD55EDA",
        ),
    );
}

#[test]
fn sm2p256v1_and_p256_match_bouncy_castle_with_sm3_and_sha256() {
    let curve = SM2P256V1.ct_curve();
    let g = SM2P256V1.ct_generator(&curve);
    let vector = |r, s| Vector {
        id: "sm2test@example.com",
        message: "hi chappy",
        x: STANDARD_KEY,
        nonce: STANDARD_NONCE,
        r,
        s,
    };
    type Sm2Curve256<'a> = &'a SecPCtCurve<SM2P256V1FieldElement>;
    check::<Sm2Curve256<'_>, _>(
        &g,
        Sm3Digest::new,
        &vector(
            "05890B9077B92E47B17A1FF42A814280E556AFD92B4A98B9670BF8B1A274C2FA",
            "E3ABBB8DB2B6ECD9B24ECCEA7F679FB9A4B1DB52F4AA985E443AD73237FA1993",
        ),
    );
    check::<Sm2Curve256<'_>, _>(
        &g,
        Sha256Digest::new,
        &vector(
            "94DA20EA69E4FC70692158BF3D30F87682A4B2F84DF4A4829A1EFC5D9C979D3F",
            "EE15AF8D455B728AB80E592FCB654BF5B05620B2F4D25749D263D5C01FAD365F",
        ),
    );

    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let g = SECP256R1.ct_generator(&curve);
    let vector = |r, s| Vector {
        id: "sm2_p256_test@example.com",
        message: "no backdoors here",
        x: STANDARD_KEY,
        nonce: STANDARD_NONCE,
        r,
        s,
    };
    check::<&FpCtCurve<'_>, _>(
        &g,
        Sm3Digest::new,
        &vector(
            "96AA39A0C4A5C454653F394E86386F2E38BE14C57D0E555F3A27A5CEF30E51BD",
            "62372BE4AC97DBE725AC0B279BB8FD15883858D814FD792DDB0A401DCC988E70",
        ),
    );
    check::<&FpCtCurve<'_>, _>(
        &g,
        Sha256Digest::new,
        &vector(
            "503D234A22123D7029271EB9E0D763619A69868DE8296C13EDD4CA32D280CFDE",
            "0BDE97699B77268584DDD238DA120095F01130AD2DB37184270F37C02FB2E86B",
        ),
    );
}

fn f2m_curve() -> F2mCtCurve {
    F2mCtCurve::new(
        F2mField::trinomial(257, 12).unwrap(),
        &[0; 33],
        &bytes("00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B"),
        Some(integer(
            "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D",
        )),
        Some(PaddedBigUint::from(4u8)),
    )
    .unwrap()
}

fn f2m_generator(curve: &F2mCtCurve) -> <&F2mCtCurve as Curve>::Point {
    curve
        .create_point(
            &bytes("00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD"),
            &bytes("013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E"),
        )
        .unwrap()
}

const F2M_KEY: &str = "771EF3DBFF5F1CDC32B9C572930476191998B2BF7CB981D7F5B39202645F0931";

#[test]
fn the_f2m_curve_with_cofactor_four_matches_bouncy_castle() {
    let curve = f2m_curve();
    check::<&F2mCtCurve, _>(
        &f2m_generator(&curve),
        Sm3Digest::new,
        &Vector {
            id: "ALICE123@YAHOO.COM",
            message: "message digest",
            x: F2M_KEY,
            nonce: "36CD79FC8E24B7357A8A7B4A46D454C397703D6498158C605399B341ADA186D6",
            r: "6D3FBA26EAB2A1054F5D198332E335817C8AC453ED26D3391CD4439D825BF25B",
            s: "3124C5688D95F0A10252A9BED033BEC84439DA384621B6D6FAD77F94B74A9556",
        },
    );
}

#[test]
fn one_signer_signs_three_messages_in_a_row_and_resets_between_them() {
    let curve = SM2P256V1.ct_curve();
    let g = SM2P256V1.ct_generator(&curve);
    type C<'a> = &'a SecPCtCurve<SM2P256V1FieldElement>;
    let d = integer(STANDARD_KEY);
    let private_key = EcPrivateKey::<C<'_>>::new(g.clone(), d.clone()).unwrap();
    let public_key = EcPublicKey::<C<'_>>::new(g.clone(), &C::multiply(&g, &d)).unwrap();
    let message = b"hi chappy";

    let mut signer = Sm2Signer::new(RandomDsaKCalculator::new(rand::rng()));
    signer.init(&private_key).unwrap();
    let mut signatures = Vec::new();
    for round in 0..3 {
        if round == 2 {
            signer.update(&[0]).unwrap();
            signer.reset();
        }
        signer.update(message).unwrap();
        let mut signature = vec![0; signer.max_signature_size()];
        let length = signer.generate_signature(&mut signature).unwrap();
        signature.truncate(length);
        signatures.push(signature);
    }

    let mut verifier = Sm2Signer::new(RandomDsaKCalculator::new(rand::rng()));
    verifier.init(&public_key).unwrap();
    for (round, signature) in signatures.iter().enumerate() {
        if round == 2 {
            verifier.update(&[0]).unwrap();
            verifier.reset();
        }
        verifier.update(message).unwrap();
        assert!(verifier.verify_signature(signature).unwrap());
    }
}

#[test]
fn r_and_s_outside_one_to_n_minus_one_do_not_verify() {
    let curve = f2m_curve();
    let g = f2m_generator(&curve);
    let d = integer(F2M_KEY);
    let public_key =
        EcPublicKey::<&F2mCtCurve>::new(g.clone(), &<&F2mCtCurve>::multiply(&g, &d)).unwrap();
    let n = integer("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D");
    let eight = PaddedBigUint::from(8u8);
    let plain = |r: &PaddedBigUint, s: &PaddedBigUint| {
        let mut out = vec![0u8; 64];
        let (r, s) = (ArrayEncoding::<u8>::to_be(r), ArrayEncoding::<u8>::to_be(s));
        out[32 - r.len().min(32)..32].copy_from_slice(&r[r.len().saturating_sub(32)..]);
        out[64 - s.len().min(32)..].copy_from_slice(&s[s.len().saturating_sub(32)..]);
        out
    };
    let mut verifier =
        Sm2Signer::new(RandomDsaKCalculator::new(rand::rng())).with_encoding(PlainDsaEncoding);
    verifier.init(&public_key).unwrap();
    for (r, s) in [
        (PaddedBigUint::from(0u8), eight.clone()),
        (eight.clone(), PaddedBigUint::from(0u8)),
        (n.clone(), eight.clone()),
        (eight.clone(), n.clone()),
    ] {
        verifier.update(&[0; 20]).unwrap();
        assert!(!verifier.verify_signature(&plain(&r, &s)).unwrap());
    }
}

#[test]
fn errors_are_reported() {
    let curve = SM2P256V1.ct_curve();
    let g = SM2P256V1.ct_generator(&curve);
    type C<'a> = &'a SecPCtCurve<SM2P256V1FieldElement>;
    let d = integer(STANDARD_KEY);
    let private_key = EcPrivateKey::<C<'_>>::new(g.clone(), d.clone()).unwrap();
    let public_key = EcPublicKey::<C<'_>>::new(g.clone(), &C::multiply(&g, &d)).unwrap();

    let mut signer = Sm2Signer::<C<'_>, _>::new(RandomDsaKCalculator::new(rand::rng()));
    assert_eq!(signer.update(b"x"), Err(Sm2Error::NotInitialized));
    signer.init(&public_key).unwrap();
    assert_eq!(
        signer.generate_signature(&mut [0; 72]),
        Err(Sm2Error::WrongKeyForSigning)
    );
    signer.init(&private_key).unwrap();
    assert_eq!(
        signer.verify_signature(&[0; 72]),
        Err(Sm2Error::WrongKeyForSigning)
    );
    assert!(matches!(
        signer.init(&Sm2SignerParams::new(private_key).with_user_id(vec![0; 8192])),
        Err(Sm2Error::InvalidUserId)
    ));

    // d = n − 1 時 1 + d 沒有反元素。
    let n = integer("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
    let largest = EcPrivateKey::<C<'_>>::new(g, n - 1u32).unwrap();
    assert_eq!(signer.init(&largest), Err(Sm2Error::PrivateKeyOutOfRange));
}
