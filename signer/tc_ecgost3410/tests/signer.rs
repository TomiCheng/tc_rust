//! `EcGost3410Signer`：Bouncy Castle `ECGost3410Test` 的固定向量（GOST R 34.10-2001 標準的
//! 範例，固定 k）、測試參數與 CryptoPro A／B／C 參數上的隨機簽章，以及 BC 以
//! `Gost3410DigestSigner` 算出的 s ‖ r 簽章（GOST R 34.11-2012 256 與 34.11-94）。

use num_traits::Num;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_dsa::{
    Dsa, DsaDigestSignerError, DsaInit, DsaKCalculator, Gost3410DigestSigner, RandomDsaKCalculator,
};
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_ecgost3410::{EcGost3410Error, EcGost3410Signer};
use tc_fp_curve::{FpCtCurve, FpField};
use tc_gost3411::{Gost3411_2012_256Digest, Gost3411Digest};
use tc_signer::{Signer, SignerInit};

type Fp<'a> = &'a FpCtCurve<'a>;

fn decimal(text: &str) -> PaddedBigUint {
    PaddedBigUint::from_str_radix(text, 10).unwrap()
}

fn hex(text: &str) -> PaddedBigUint {
    PaddedBigUint::from_str_radix(text, 16).unwrap()
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// 十進位的 p、a、b、q 與 G 的座標。
struct Domain {
    p: &'static str,
    a: &'static str,
    b: &'static str,
    q: &'static str,
    x: &'static str,
    y: &'static str,
}

/// gostR3410-2001-TestParamSet。
const TEST: Domain = Domain {
    p: "57896044618658097711785492504343953926634992332820282019728792003956564821041",
    a: "7",
    b: "43308876546767276905765904595650931995942111794451039583252968842033849580414",
    q: "57896044618658097711785492504343953927082934583725450622380973592137631069619",
    x: "2",
    y: "4018974056539037503335449422937059775635739389905545080690979365213431566280",
};

/// gostR3410-2001-CryptoPro-A-ParamSet。
const CRYPTO_PRO_A: Domain = Domain {
    p: "115792089237316195423570985008687907853269984665640564039457584007913129639319",
    a: "115792089237316195423570985008687907853269984665640564039457584007913129639316",
    b: "166",
    q: "115792089237316195423570985008687907853073762908499243225378155805079068850323",
    x: "1",
    y: "64033881142927202683649881450433473985931760268884941288852745803908878638612",
};

/// gostR3410-2001-CryptoPro-B-ParamSet。
const CRYPTO_PRO_B: Domain = Domain {
    p: "57896044618658097711785492504343953926634992332820282019728792003956564823193",
    a: "57896044618658097711785492504343953926634992332820282019728792003956564823190",
    b: "28091019353058090096996979000309560759124368558014865957655842872397301267595",
    q: "57896044618658097711785492504343953927102133160255826820068844496087732066703",
    x: "1",
    y: "28792665814854611296992347458380284135028636778229113005756334730996303888124",
};

/// gostR3410-2001-CryptoPro-C-ParamSet。
const CRYPTO_PRO_C: Domain = Domain {
    p: "70390085352083305199547718019018437841079516630045180471284346843705633502619",
    a: "70390085352083305199547718019018437841079516630045180471284346843705633502616",
    b: "32858",
    q: "70390085352083305199547718019018437840920882647164081035322601458352298396601",
    x: "0",
    y: "29818893917731240733471273240314769927240550812383695689146495261604565990247",
};

/// BC `ECGost3410Test` 的雜湊訊息。
const HASH_MESSAGE: &str = "3042453136414534424341374533364339313734453431443642453241453435";

/// 以 `domain` 建好的域、曲線，交給 `body` 使用。
fn with_curve(domain: &Domain, body: impl FnOnce(&FpCtCurve<'_>)) {
    let field = FpField::new(decimal(domain.p)).unwrap();
    let curve = FpCtCurve::new(
        &field,
        &decimal(domain.a),
        &decimal(domain.b),
        Some(decimal(domain.q)),
        Some(PaddedBigUint::from(1u8)),
    )
    .unwrap();
    body(&curve);
}

fn generator<'a>(curve: &'a FpCtCurve<'a>, domain: &Domain) -> <Fp<'a> as Curve>::Point {
    curve
        .create_point(&decimal(domain.x), &decimal(domain.y))
        .unwrap()
}

/// 固定的 k，代替 BC 測試的 `FixedSecureRandom`。
struct FixedK(PaddedBigUint);

impl DsaKCalculator<PaddedBigUint> for FixedK {
    fn init(&mut self, _n: &PaddedBigUint, _d: &PaddedBigUint, _message: &[u8]) {}

    fn next_k(&mut self) -> PaddedBigUint {
        self.0.clone()
    }
}

#[test]
fn the_standard_example_matches_bouncy_castle() {
    with_curve(&TEST, |curve| {
        let g = generator(curve, &TEST);
        let d = decimal(
            "55441196065363246126355624130324183196576709222340016572108097750006097525544",
        );
        let k = decimal(
            "53854137677348463731403841147996619241504003434302020712960838528893196233395",
        );
        // BC 把 e 的大端序位元組反過來當訊息，讓 GOST 讀回同一個 e。
        let mut message = bytes(&format!(
            "{:0>64}",
            "2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5"
        ));
        message.reverse();

        let mut signer = EcGost3410Signer::new(FixedK(k));
        signer
            .init(&EcPrivateKey::<Fp<'_>>::new(g.clone(), d).unwrap())
            .unwrap();
        let (r, s) = signer.generate_signature(&message).unwrap();
        assert_eq!(
            r,
            decimal(
                "29700980915817952874371204983938256990422752107994319651632687982059210933395"
            )
        );
        assert_eq!(
            s,
            decimal("574973400270084654178925310019147038455227042649098563933718999175515839552")
        );

        let q = curve
            .create_point(
                &decimal(
                    "57520216126176808443631405023338071176630104906313632182896741342206604859403",
                ),
                &decimal(
                    "17614944419213781543809391949654080031942662045363639260709847859438286763994",
                ),
            )
            .unwrap();
        let mut verifier = EcGost3410Signer::new(FixedK(PaddedBigUint::from(1u8)));
        verifier
            .init(&EcPublicKey::<Fp<'_>>::new(g, &q).unwrap())
            .unwrap();
        assert!(verifier.verify_signature(&message, &r, &s).unwrap());
        assert!(!verifier.verify_signature(&message[1..], &r, &s).unwrap());
    });
}

#[test]
fn random_keys_sign_and_verify_on_the_test_and_crypto_pro_parameters() {
    let mut digest = Gost3411Digest::new();
    digest.update(b"Message for sign");
    let mut gost_hash = vec![0; 32];
    digest.do_final(&mut gost_hash);
    for (domain, message) in [
        (&TEST, gost_hash),
        (&CRYPTO_PRO_A, bytes(HASH_MESSAGE)),
        (&CRYPTO_PRO_B, bytes(HASH_MESSAGE)),
        (&CRYPTO_PRO_C, bytes(HASH_MESSAGE)),
    ] {
        with_curve(domain, |curve| {
            let g = generator(curve, domain);
            let n = decimal(domain.q);
            let mut rng = rand::rng();
            let mut k = RandomDsaKCalculator::new(&mut rng);
            k.init(&n, &n, &[]);
            let d = k.next_k();
            let q = <Fp<'_>>::multiply(&g, &d);

            let mut signer = EcGost3410Signer::new(RandomDsaKCalculator::new(rand::rng()));
            signer
                .init(&EcPrivateKey::<Fp<'_>>::new(g.clone(), d).unwrap())
                .unwrap();
            let (r, s) = signer.generate_signature(&message).unwrap();
            let mut verifier = EcGost3410Signer::new(RandomDsaKCalculator::new(rand::rng()));
            verifier
                .init(&EcPublicKey::<Fp<'_>>::new(g, &q).unwrap())
                .unwrap();
            assert!(verifier.verify_signature(&message, &r, &s).unwrap());
            assert!(!verifier.verify_signature(&message, &s, &r).unwrap());
        });
    }
}

/// BC 的 `Gost3410DigestSigner(new ECGost3410Signer(), digest)`，在 CryptoPro-A 上以固定的
/// d 與 k 簽 "Message for sign" 的結果。
const D: &str = "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28";
const K: &str = "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3";
const SIGNATURE_2012: &str = "a2e6f04d0ad0a1180731f04d744f695bc5757c49798d22154f585bfbe8d6ed1b74e939c637a79a5b7e39dc15976befb324acdb74e2fa8d434aba0da9ebf8de8f";
const SIGNATURE_94: &str = "c497a090a4113db8b6490327d80f39d433f4ac933f8458563b25cf5a0841697374e939c637a79a5b7e39dc15976befb324acdb74e2fa8d434aba0da9ebf8de8f";

fn digest_sign_and_verify<D2: Digest>(digest: impl Fn() -> D2, expected: &str) {
    with_curve(&CRYPTO_PRO_A, |curve| {
        let g = generator(curve, &CRYPTO_PRO_A);
        let q = <Fp<'_>>::multiply(&g, &hex(D));
        let mut signer = Gost3410DigestSigner::new(EcGost3410Signer::new(FixedK(hex(K))), digest());
        signer
            .init(&EcPrivateKey::<Fp<'_>>::new(g.clone(), hex(D)).unwrap())
            .unwrap();
        signer.update(b"Message for sign").unwrap();
        let mut signature = vec![0; signer.max_signature_size()];
        let length = signer.generate_signature(&mut signature).unwrap();
        assert_eq!(signature[..length], bytes(expected)[..]);

        let mut verifier =
            Gost3410DigestSigner::new(EcGost3410Signer::new(FixedK(hex(K))), digest());
        verifier
            .init(&EcPublicKey::<Fp<'_>>::new(g, &q).unwrap())
            .unwrap();
        verifier.update(b"Message for sign").unwrap();
        assert!(verifier.verify_signature(&signature[..length]).unwrap());
        verifier.update(b"Message for sign").unwrap();
        assert!(!verifier.verify_signature(&signature[..length - 1]).unwrap());
    });
}

#[test]
fn the_digest_signer_writes_s_then_r_as_bouncy_castle_does() {
    digest_sign_and_verify(Gost3411_2012_256Digest::default, SIGNATURE_2012);
    digest_sign_and_verify(Gost3411Digest::new, SIGNATURE_94);
}

#[test]
fn errors_are_reported() {
    with_curve(&CRYPTO_PRO_A, |curve| {
        let g = generator(curve, &CRYPTO_PRO_A);
        let q = <Fp<'_>>::multiply(&g, &hex(D));
        let mut signer = EcGost3410Signer::new(FixedK(hex(K)));
        assert_eq!(
            signer.generate_signature(&[1]),
            Err(EcGost3410Error::NotInitialized)
        );
        signer
            .init(&EcPublicKey::<Fp<'_>>::new(g.clone(), &q).unwrap())
            .unwrap();
        assert_eq!(
            signer.generate_signature(&[1]),
            Err(EcGost3410Error::NotForSigning)
        );
        // r 或 s 不在 [1, n − 1]、e ≡ 0 時視為不符。
        let one = PaddedBigUint::from(1u8);
        let zero = PaddedBigUint::from(0u8);
        assert!(!signer.verify_signature(&[1], &zero, &one).unwrap());
        assert!(
            !signer
                .verify_signature(&[1], &one, &decimal(CRYPTO_PRO_A.q))
                .unwrap()
        );
        assert!(!signer.verify_signature(&[0], &one, &one).unwrap());
        signer
            .init(&EcPrivateKey::<Fp<'_>>::new(g.clone(), hex(D)).unwrap())
            .unwrap();
        assert_eq!(
            signer.verify_signature(&[1], &one, &one),
            Err(EcGost3410Error::NotForVerifying)
        );

        let mut digest_signer =
            Gost3410DigestSigner::new(EcGost3410Signer::new(FixedK(hex(K))), Gost3411Digest::new());
        assert_eq!(
            digest_signer.update(b"x"),
            Err(DsaDigestSignerError::NotInitialized)
        );
        digest_signer
            .init(&EcPublicKey::<Fp<'_>>::new(g, &q).unwrap())
            .unwrap();
        assert_eq!(
            digest_signer.generate_signature(&mut [0; 64]),
            Err(DsaDigestSignerError::NotForSigning)
        );
    });
}
