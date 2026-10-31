//! `Iso9796d2Signer` 與 `Iso9796d2PssSigner`：Bouncy Castle `ISO9796Test` 的方案 1 向量
//! （RIPEMD-128 整則、RIPEMD-160 部分還原）、方案 2／3 向量（固定 salt、salt 長度 0、空訊息）、
//! 訊息邊界、先還原再驗證、ShortPartial、FullMessage、格式錯誤的簽章，以及 BC 漏掉的
//! M1 比對。

use num_traits::Num;
use tc_bigint::PaddedBigUint;
use tc_ripemd::{RipeMd128Digest, RipeMd160Digest};
use tc_rsa::{RsaEngine, RsaKey, RsaKeyOwned};
use tc_rsa_signer::{Iso9796d2Error, Iso9796d2PssSigner, Iso9796d2Signer};
use tc_sha::{Sha1Digest, Sha256Digest};
use tc_signer::{Signer, SignerInit, SignerWithRecovery};

const MOD3: &str = "ffffffff78f6c55506c59785e871211ee120b0b5dd644aa796d82413a47b24573f1be5745b5cd9950f6b389b52350d4e01e90009669a8720bf265a2865994190a661dea3c7828e2e7ca1b19651adc2d5";
const PUB3: &str = "3";
const PRI3: &str = "2aaaaaaa942920e38120ee965168302fd0301d73a4e60c7143ceb0adf0bf30b9352f50e8b9e4ceedd65343b2179005b2f099915e4b0c37e41314bb0821ad8330d23cba7f589e0f129b04c46b67dfce9d";
const MOD6: &str = "b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5";
const PUB6: &str = "11";
const PRI6: &str = "92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619";
const MSG4: &str = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
const SIG4: &str = "374695b7ee8b273925b4656cc2e008d41463996534aa5aa5afe72a52ffd84e118085f8558f36631471d043ad342de268b94b080bee18a068c10965f581e7f32899ad378835477064abed8ef3bd530fce";
const MSG5: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const SIG5: &str = "5cf9a01854dbacaec83aae8efc563d74538192e95466babacd361d7c86000fe42dcb4581e48e4feb862d04698da9203b1803b262105104d510b365ee9c660857ba1c001aa57abfd1c8de92e47c275cae";
const MSG7: &str = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70716f70717270717273";
const MSG8: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba98";
const MSG9: &str = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70716f707172707172737172737472737475737475767475767775767778767778797778797a78797a61797a61627a6162636162636462636465";
const SIG6: &str = "008df6d3e7d4381ee36ec8ec7c1067db3b28da9e06a31b16ebb30c004dcd7a7904a799445d57b4fe90fb697b1e747c38436edaf64584b61dd1c4ced18f4098a0cf0a50953daf56e18284f42826e00e8bd009003e475904da186acfe79c578af3b093a32d0f8ae8ec46853e803ec2b6cf09d8066d3d84e2862853b8a6d9ec66b9ec";
const SIG7: &str = "2486dd61e560e661511db92f41045a87cbbb78ce577d28da533bc15fdf9cbc2748311a5faa6501270b46414ba3549de34160c1ef18eff339eeeae2c53f7ed4a5fddc19c5b3f5c391e8efb5548555d478f0698ec351f6a4974c9c74f0a0eba9fc03db9253f41f02ffc5f03cb9d1973946993aa3f831aa1d9e73a783e67bf7695d";
const SIG8: &str = "3d853e02ccea35ac803227458aaf5c964387e20390a476419e853ed415b3ad2ad750d19b4e4667597c1863ea2b0aa35fdbb4de589c4663583674e2c8d15d07daa54ff389ae96d78cceb2b5a50b649362357042b2c40d780361b7f6f089c7e27e92d21db1b3e3d368582e3dfdcf0312f727743c09c5c2cb3c0552b78db71be278";
const SIG9: &str = "5cf8d66c115143929ce7b568c14fef2faf5fad18b19d94b128be1f49dcc2168d51777fc23e448f84b0253b99fe735f2102314533b754b1ebf08a29085e9392fb6f4550be8948e7b9a55060b74a87d57aa6d82475176d2f7776d873afc4349cdf207a90304469f6256d83274bb698c6dabe9b209b8e6100f14d1ce290eaca175b";
const MOD10: &str = "B3ABE6D91A4020920F8B3847764ECB34C4EB64151A96FDE7B614DC986C810FF2FD73575BDF8532C06004C8B4C8B64F700A50AEC68C0701ED10E8D211A4EA554D";
const PRI10: &str = "AEE76AE4716F77C5782838F328327012C097BD67E5E892E75C1356E372CCF8EE1AA2D2CBDFB4DA19F703743F7C0BA42B2D69202BA7338C294D1F8B6A5771FF41";
const MOD13: &str = "CDCBDABBF93BE8E8294E32B055256BBD0397735189BF75816341BB0D488D05D627991221DF7D59835C76A4BB4808ADEEB779E7794504E956ADC2A661B46904CDC71337DD29DDDD454124EF79CFDD7BC2C21952573CEFBA485CC38C6BD2428809B5A31A898A6B5648CAA4ED678D9743B589134B7187478996300EDBA16271A861";
const PRI13: &str = "4BA6432AD42C74AA5AFCB6DF60FD57846CBC909489994ABD9C59FE439CC6D23D6DE2F3EA65B8335E796FD7904CA37C248367997257AFBD82B26F1A30525C447A236C65E6ADE43ECAAF7283584B2570FA07B340D9C9380D88EAACFFAEEFE7F472DBC9735C3FF3A3211E8A6BBFD94456B6A33C17A2C4EC18CE6335150548ED126D";
const ARGS0: &str = "482E20D1EDDED34359C38F5E7C01203F9D6B2641CDCA5C404D49ADAEDE034C7481D781D043722587761C90468DE69C6585A1E8B9C322F90E1B580EEDAB3F6007D0C366CF92B4DB8B41C8314929DCE2BE889C0129123484D2FD3D12763D2EBFD12AC8E51D7061AFCA1A53DEDEC7B9A617472A78C952CCC72467AE008E5F132994";
const LONG_MESSAGE: &str = "5553482b312b534536383031353332393731392b322b312b362b322b312b313a3a393939393939393939393939393a3a392b323a3a373737373737373737373737373a3a392b2b353a32303133303430353a313133353230275553412b313a3a3a31363a31275553432b34666239376331613432396462326436275553412b363a31363a313a31303a312b31343a323034382b31323afef9f74b487de9e3617e63cde8e654c5785df35e61d2d3fcef51e5f95d6b7c71d45efacf5e68c7574bdd6fc7d8635cf1c2f9d051c1415974f8dcf162ed76e8c34ffd7bd97afe686cd5426a54fbe9f842db7977e7e0d8f4dadb64d1edc7e477daebd35846e1efd5604eea57e2ccd9ccf66f5762687d4ceae07fdac346d77e64d6dfe25cfd7cf4edf4e5f2c4e25644faffd052f3c5456c75da657c7c4cde77444c50fb7df8c8fe685162e2fc59767bdf72de58544278eccace60f3fc7bd3dc6671fd724c6c5a6ac8e66379dce1eaf66bd6fac3eb5e5341f37bc2d249dbd6cdd87bf36f67f5c461da5e5eda7f4ff0f5da51d9dafbfc7cee64424a61cec94a4bf8fe4dfbc844486dcadf6d54de56d47e75c56879e453e357e6ccc7f37fc46758e5f860c3627e5d2b31333af04140412742474d2b3338302b39393939393939392744544d2b3133373a32303133303430353a313032274654582b4141492b2b2b494e564f4943452054455354275246462b4f4e3a313233343536275246462b44513a3232323232323232322744544d2b3137313a32303133303430313a313032274e41442b53552b393939393939393939393939393a3a392b2b5445535420535550504c4945523a3a547261736520726567697374657220585858585858582b54657374206164647265737320737570706c6965722b436974792b2b31323334352b4445275246462b56413a413132333435363738274e41442b53434f2b393939393939393939393939393a3a392b2b5445535420535550504c4945523a3a547261736520726567697374657220585858585858582b54657374206164647265737320737570706c6965722b436974792b2b31323334352b4445275246462b56413a413132333435363738274e41442b42592b383838383838383838383838383a3a39274e41442b49562b373737373737373737373737373a3a392b2b544553542042555945522b5465737420616464726573732062757965722b43697479322b2b35343332312b4445275246462b56413a4a3837363534333231274e41442b42434f2b373737373737373737373737373a3a392b2b544553542042555945522b5465737420616464726573732062757965722b43697479322b2b35343332312b4445275246462b56413a4a3837363534333231274e41442b44502b383838383838383838383838383a3a39274e41442b50522b373737373737373737373737373a3a39274355582b323a4555523a34275041542b33352744544d2b31333a32303133303632343a313032274c494e2b312b2b313131313131313131313131313a454e275049412b312b414141414141413a534127494d442b462b4d2b3a3a3a50524f4455435420544553542031275154592b34373a31302e303030274d4f412b36363a372e3030275052492b4141423a312e3030275052492b4141413a302e3730275246462b4f4e3a313233343536275246462b44513a323232323232323232275441582b372b5641542b2b2b3a3a3a32312e30303027414c432b412b2b2b312b5444275043442b313a33302e303030274d4f412b3230343a332e3030274c494e2b322b2b323232323232323232323232323a454e275049412b312b424242424242423a534127494d442b462b4d2b3a3a3a50524f4455435420544553542032275154592b34373a32302e303030274d4f412b36363a38302e3030275052492b4141423a352e3030275052492b4141413a342e3030275246462b4f4e3a313233343536275246462b44513a323232323232323232275441582b372b5641542b2b2b3a3a3a32312e30303027414c432b412b2b2b312b5444275043442b313a32302e303030274d4f412b3230343a32302e303027554e532b5327434e542b323a32274d4f412b37393a38372e3030274d4f412b3133393a3130352e3237274d4f412b3132353a38372e3030274d4f412b3236303a302e3030274d4f412b3235393a302e3030274d4f412b3137363a31382e3237275441582b372b5641542b2b2b3a3a3a32312e303030274d4f412b3137363a31382e3237274d4f412b3132353a38372e303027";
const SHORT_PARTIAL_SIG: &str = "b1bf32c8a93a1ccd5c26120249c331ed0450ba7472ad9d5f6c8e36f93f930463633a49efccabaf1bb69fb465fb3bf457b98824e8b4f1a57bfbf8ee67a1484c06c4763ca687bdebb2954d5648f983c430ae8b7929e1faea547d30f158e99790ac2aa06c98a91b182284fac98cd31157858c55f105130765ec58d0908858873e0c1ba5f5b365435840f59dd00f7d3fae04b94218cf5b649039cb166c10d7dfcf26ed5af28ac84089e69156164ac06c67fecab3a9719c31e902f82245ef8e5e627fcae432d4edc5258772a2abe36113c1bb7a987812bdfbd2f7944c4b8a52261f96839c9ce769770ef1014ec553dbac5dace0674f20c0e89c4c801ddae7ce882196";
const SHORT_PARTIAL_RECOVERED: &str = "5553482b312b534536383031353332393731392b322b312b362b322b312b313a3a393939393939393939393939393a3a392b323a3a373737373737373737373737373a3a392b2b353a32303133303430353a313133";
const SHORT_PARTIAL_MOD: &str = "b9b70b083da9e37e23cde8e654855db31e21d2d3fc11a5f91d2b3c311efa8f5e28c757dd6fc798631cb1b9d051c14119749cb122ad76e8c3fd7bd93abe282c026a14fba9f8023977a7a0d8b49a24d1ad87e4379a931846a1ef9520ea57e28c998cf65722683d0caaa0da8306973e2496a25cbd3cb4adb4b284e25604fabf12f385456c75da7c3c4cde37440cfb7db8c8fe6851e2bc59767b9f7218540238ac8acef3bc7bd3dc6671320c2c1a2ac8a6799ce1eaf62b9683ab1e1341b37b9249dbd6cd987b2f27b5c4619a1eda7f0fb0b59a519afbbc3cee640261cec90a4bb8fefbc844082dca9f549e56943e758579a453a357e6ccb37fc46718a5b8c3227e5d";

fn int(hex: &str) -> PaddedBigUint {
    PaddedBigUint::from_str_radix(hex, 16).unwrap()
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// BC 的 `BigInteger.ToByteArray` 會多一個正負號位元組；簽章與模數等長。
fn signature(hex: &str, length: usize) -> Vec<u8> {
    let bytes = bytes(hex);
    let mut padded = vec![0; length];
    let kept = bytes.len().min(length);
    padded[length - kept..].copy_from_slice(&bytes[bytes.len() - kept..]);
    padded
}

fn keys(n: &str, e: &str, d: &str) -> (RsaKey, RsaKey) {
    (
        RsaKeyOwned::new(false, int(n), int(e)).into(),
        RsaKeyOwned::new(true, int(n), int(d)).into(),
    )
}

fn sign<S: Signer + SignerInit<RsaKey>>(signer: &mut S, key: &RsaKey, message: &[u8]) -> Vec<u8>
where
    <S as Signer>::Error: core::fmt::Debug,
    <S as SignerInit<RsaKey>>::Error: core::fmt::Debug,
{
    signer.init(key).unwrap();
    signer.update(message).unwrap();
    let mut signature = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut signature).unwrap();
    signature.truncate(length);
    signature
}

fn verify<S: Signer + SignerInit<RsaKey>>(
    signer: &mut S,
    key: &RsaKey,
    message: &[u8],
    signature: &[u8],
) -> bool
where
    <S as Signer>::Error: core::fmt::Debug,
    <S as SignerInit<RsaKey>>::Error: core::fmt::Debug,
{
    signer.init(key).unwrap();
    signer.update(message).unwrap();
    signer.verify_signature(signature).unwrap()
}

#[test]
fn scheme_1_with_a_full_message_matches_bouncy_castle_test_4() {
    let (public, private) = keys(MOD3, PUB3, PRI3);
    let message = bytes(MSG4);
    let mut signer = Iso9796d2Signer::new(RsaEngine::new(), RipeMd128Digest::default());
    let data = sign(&mut signer, &private, &message);
    assert_eq!(data, bytes(SIG4));
    assert!(verify(&mut signer, &public, &message, &data));
    assert!(signer.has_full_message());

    let mut verifier = Iso9796d2Signer::new(RsaEngine::new(), RipeMd128Digest::default());
    verifier.init(&public).unwrap();
    assert!(verifier.verify_signature(&data).unwrap());
    assert_eq!(verifier.recovered_message(), Some(&message[..]));

    verifier.update_with_recovered_message(&data).unwrap();
    assert_eq!(verifier.recovered_message(), Some(&message[..]));
    assert!(verifier.verify_signature(&data).unwrap());
    assert_eq!(verifier.recovered_message(), Some(&message[..]));

    // 已還原整則訊息，又給一次訊息就不符。
    verifier.update_with_recovered_message(&data).unwrap();
    verifier.update(&message).unwrap();
    assert!(!verifier.verify_signature(&data).unwrap());
}

#[test]
fn scheme_1_with_a_partial_message_matches_bouncy_castle_test_5() {
    let (public, private) = keys(MOD3, PUB3, PRI3);
    let message = bytes(MSG5);
    let mut signer = Iso9796d2Signer::implicit(RsaEngine::new(), RipeMd160Digest::default());
    let data = sign(&mut signer, &private, &message);
    assert_eq!(data, bytes(SIG5));
    assert!(verify(&mut signer, &public, &message, &data));
    assert!(!signer.has_full_message());
    let recovered = signer.recovered_message().unwrap().to_vec();
    assert!(recovered.len() < message.len());
    assert!(message.starts_with(&recovered));

    let mut verifier = Iso9796d2Signer::implicit(RsaEngine::new(), RipeMd160Digest::default());
    verifier.init(&public).unwrap();
    verifier.update_with_recovered_message(&data).unwrap();
    assert_eq!(verifier.recovered_message(), Some(&recovered[..]));
    assert!(!verifier.has_full_message());
    verifier.update(&message[recovered.len()..]).unwrap();
    assert!(verifier.verify_signature(&data).unwrap());

    verifier.update_with_recovered_message(&data).unwrap();
    verifier.update(&message).unwrap();
    assert!(!verifier.verify_signature(&data).unwrap());
}

#[test]
fn scheme_2_and_3_match_bouncy_castle_tests_6_to_9() {
    let (public, private) = keys(MOD6, PUB6, PRI6);
    let rng = rand::rng;
    for (signer, message, expected) in [
        (
            Iso9796d2PssSigner::implicit(RsaEngine::new(), RipeMd160Digest::default(), 20, rng())
                .with_salt(bytes("61DF870C4890FE85D6E3DD87C3DCE3723F91DB49")),
            Vec::new(),
            SIG6,
        ),
        (
            Iso9796d2PssSigner::new(RsaEngine::new(), RipeMd160Digest::default(), 20, rng())
                .with_salt(bytes("78E293203CBA1B7F92F05F4D171FF8CA3E738FF8")),
            bytes(MSG8),
            SIG8,
        ),
        (
            Iso9796d2PssSigner::implicit(RsaEngine::new(), RipeMd160Digest::default(), 0, rng()),
            bytes(MSG9),
            SIG9,
        ),
    ] {
        let mut signer = signer;
        let data = sign(&mut signer, &private, &message);
        assert_eq!(data, signature(expected, 128));
        assert!(verify(&mut signer, &public, &message, &data));
    }

    // 方案 3：SHA-1、salt 長度 0，訊息整則還原。
    let mut signer = Iso9796d2PssSigner::new(RsaEngine::new(), Sha1Digest::default(), 0, rng())
        .with_salt(Vec::new());
    let message = bytes(MSG7);
    let data = sign(&mut signer, &private, &message);
    assert_eq!(data, signature(SIG7, 128));
    assert!(verify(&mut signer, &public, &message, &data));
    assert_eq!(signer.recovered_message(), Some(&message[..]));
}

#[test]
fn messages_one_byte_longer_or_shorter_do_not_verify_in_either_scheme() {
    let (public, private) = keys(MOD10, "10001", PRI10);
    let m1 = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    let m2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
    let m3 = [1, 2, 3, 4, 5, 6, 7, 8];

    let mut pss = Iso9796d2PssSigner::new(RsaEngine::new(), Sha1Digest::default(), 20, rand::rng());
    let data = sign(&mut pss, &private, &m1);
    assert!(!verify(&mut pss, &public, &m2, &data));
    assert!(!verify(&mut pss, &public, &m3, &data));
    assert!(verify(&mut pss, &public, &m1, &data));

    let mut regular = Iso9796d2Signer::new(RsaEngine::new(), Sha1Digest::default());
    let data = sign(&mut regular, &private, &m1);
    assert!(!verify(&mut regular, &public, &m2, &data));
    assert!(!verify(&mut regular, &public, &m3, &data));
    assert!(verify(&mut regular, &public, &m1, &data));
}

#[test]
fn a_changed_m1_does_not_verify_although_bouncy_castle_accepts_it() {
    let (public, private) = keys(MOD10, "10001", PRI10);
    let message = [7u8; 200];
    let mut pss = Iso9796d2PssSigner::new(RsaEngine::new(), Sha1Digest::default(), 20, rand::rng());
    let data = sign(&mut pss, &private, &message);
    assert!(verify(&mut pss, &public, &message, &data));
    let mut changed = message;
    changed[0] ^= 1;
    assert!(!verify(&mut pss, &public, &changed, &data));
}

#[test]
fn recovery_with_a_challenge_follows_bouncy_castle_test_13() {
    let (public, private) = keys(MOD13, "010001", PRI13);
    let challenge = [0u8; 8];

    let mut signer = Iso9796d2Signer::new(RsaEngine::new(), Sha256Digest::default());
    let data = sign(&mut signer, &private, &challenge);
    assert!(verify(&mut signer, &public, &challenge, &data));

    let mut sha1 = Iso9796d2Signer::implicit(RsaEngine::new(), Sha1Digest::default());
    sha1.init(&public).unwrap();
    let args0 = bytes(ARGS0);
    sha1.update_with_recovered_message(&args0).unwrap();
    sha1.update(&challenge).unwrap();
    assert!(sha1.verify_signature(&args0).unwrap());

    let nonce: Vec<u8> = (0..1024 / 8 - 1 - 32 - 2).map(|i| i as u8).collect();
    signer.init(&private).unwrap();
    signer.update(&nonce).unwrap();
    signer.update(&challenge).unwrap();
    let mut data = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut data).unwrap();
    signer.init(&public).unwrap();
    signer
        .update_with_recovered_message(&data[..length])
        .unwrap();
    signer.update(&challenge).unwrap();
    assert!(signer.verify_signature(&data[..length]).unwrap());
    assert!(!signer.has_full_message());
    assert_eq!(signer.recovered_message(), Some(&nonce[..]));
}

#[test]
fn a_short_partial_and_a_full_message_recover_as_in_bouncy_castle() {
    let public: RsaKey = RsaKeyOwned::new(false, int(SHORT_PARTIAL_MOD), int("10001")).into();
    let long_message = bytes(LONG_MESSAGE);
    let data = bytes(SHORT_PARTIAL_SIG);
    let mut pss = Iso9796d2PssSigner::new(RsaEngine::new(), Sha1Digest::default(), 20, rand::rng());
    pss.init(&public).unwrap();
    pss.update_with_recovered_message(&data).unwrap();
    let recovered = pss.recovered_message().unwrap().len();
    pss.update(&long_message[recovered..]).unwrap();
    assert!(pss.verify_signature(&data).unwrap());
    assert_eq!(
        pss.recovered_message(),
        Some(&bytes(SHORT_PARTIAL_RECOVERED)[..])
    );

    let (public, private) = keys(MOD13, "010001", PRI13);
    let challenge = [0u8; 8];
    let mut pss =
        Iso9796d2PssSigner::implicit(RsaEngine::new(), Sha256Digest::default(), 20, rand::rng());
    let data = sign(&mut pss, &private, &challenge);
    pss.init(&public).unwrap();
    pss.update_with_recovered_message(&data).unwrap();
    assert!(pss.verify_signature(&data).unwrap());
    assert_eq!(pss.recovered_message(), Some(&challenge[..]));
}

#[test]
fn malformed_signatures_are_rejected() {
    let (public, _) = keys(MOD3, PUB3, PRI3);
    let length = MOD3.len() / 2;
    for malformed in [vec![], vec![0], vec![0; length], vec![0; length + 1]] {
        let mut verifier = Iso9796d2Signer::implicit(RsaEngine::new(), Sha1Digest::default());
        verifier.init(&public).unwrap();
        assert!(!verifier.verify_signature(&malformed).unwrap());
    }
    // 全零的簽章由 RSA 引擎拒絕，BC 在這裡也是引擎的 DataLengthException。
    let mut recoverer = Iso9796d2Signer::implicit(RsaEngine::new(), Sha1Digest::default());
    recoverer.init(&public).unwrap();
    assert!(matches!(
        recoverer.update_with_recovered_message(&vec![0; length]),
        Err(Iso9796d2Error::Cipher(_))
    ));
    // 解得出、但不是 ISO 9796-2 區塊的簽章是 MalformedSignature。
    assert_eq!(
        recoverer.update_with_recovered_message(&[2]),
        Err(Iso9796d2Error::MalformedSignature)
    );
}

#[test]
fn errors_are_reported() {
    let (public, private) = keys(MOD3, PUB3, PRI3);
    let mut signer = Iso9796d2Signer::new(RsaEngine::new(), RipeMd128Digest::default());
    assert_eq!(signer.update(b"x"), Err(Iso9796d2Error::NotInitialized));
    signer.init(&public).unwrap();
    assert_eq!(
        signer.generate_signature(&mut [0; 80]),
        Err(Iso9796d2Error::NotForSigning)
    );
    signer.init(&private).unwrap();
    assert_eq!(
        signer.verify_signature(&[0; 80]),
        Err(Iso9796d2Error::NotForVerifying)
    );

    // 標明 RIPEMD-128 的簽章，以 RIPEMD-160 驗證時回傳錯誤，同 BC。
    let data = sign(
        &mut Iso9796d2Signer::new(RsaEngine::new(), RipeMd128Digest::default()),
        &private,
        &bytes(MSG4),
    );
    let mut other = Iso9796d2Signer::new(RsaEngine::new(), RipeMd160Digest::default());
    other.init(&public).unwrap();
    assert_eq!(
        other.verify_signature(&data),
        Err(Iso9796d2Error::TrailerMismatch(0x32CC))
    );

    let mut verifier = Iso9796d2Signer::new(RsaEngine::new(), RipeMd128Digest::default());
    verifier.init(&public).unwrap();
    verifier.update_with_recovered_message(&data).unwrap();
    assert_eq!(
        verifier.verify_signature(&bytes(SIG5)),
        Err(Iso9796d2Error::DifferentSignature)
    );
}
