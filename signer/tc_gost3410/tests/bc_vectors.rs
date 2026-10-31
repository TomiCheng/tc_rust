//! `Gost3410Signer` 與 `tc_gost3410_key` 的產生器：Bouncy Castle `Gost3410Test` 的十一組
//! 向量。每組以固定的亂數依序產生參數（程序 A、A'、B、B'、C）、金鑰對與簽章，比對 p、q、
//! r、s，再驗證。亂數來源照 BC 測試的 `FixedSecureRandom` 與覆寫的 `SecureRandom` 移植。
//!
//! 1024 位元的兩組 TEST 照常執行，涵蓋程序 B 與 B'；其餘七組在 debug 建置下共約 30 秒，
//! 標為 `#[ignore]`，以 `cargo test -- --ignored` 執行。

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{Dsa, DsaInit};
use tc_gost3410::Gost3410Signer;
use tc_gost3410_key::{
    Gost3410KeyGenerationParams, Gost3410KeyPairGenerator, Gost3410ParametersGenerator,
};

const HASH_MESSAGE: &str = "3042453136414534424341374533364339313734453431443642453241453435";

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn integer(hex: &str) -> PaddedBigUint {
    let Ok(value) =
        PaddedBigUint::from_be(&bytes(&format!("{:0>1$}", hex, hex.len().div_ceil(2) * 2)));
    value
}

/// 讓測試的亂數來源只需寫 `fill`。
trait Fill {
    fn fill(&mut self, output: &mut [u8]);
}

/// 以 `Fill` 實作 rand_core 的 trait。
struct Source<F>(F);

impl<F: Fill> TryRng for Source<F> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.0.fill(&mut bytes);
        Ok(u32::from_be_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.0.fill(&mut bytes);
        Ok(u64::from_be_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Infallible> {
        self.0.fill(output);
        Ok(())
    }
}

impl<F: Fill> TryCryptoRng for Source<F> {}

/// BC 的 `FixedSecureRandom`：依序交出固定的位元組，用完時 panic。
struct Fixed {
    data: Vec<u8>,
    position: usize,
}

impl Fill for Fixed {
    fn fill(&mut self, output: &mut [u8]) {
        let end = self.position + output.len();
        output.copy_from_slice(&self.data[self.position..end]);
        self.position = end;
    }
}

/// BC 測試覆寫的 `NextInt`／`NextLong`：先交出 x0 與 c，之後每次把 `d` 放在全零緩衝區的
/// 尾端，同覆寫的 `NextBytes`。
struct Overridden {
    first: Vec<Vec<u8>>,
    d: Vec<u8>,
}

impl Fill for Overridden {
    fn fill(&mut self, output: &mut [u8]) {
        if !self.first.is_empty() {
            let value = self.first.remove(0);
            assert_eq!(value.len(), output.len(), "x0 and c are read whole");
            output.copy_from_slice(&value);
            return;
        }
        output.fill(0);
        let start = output.len() - self.d.len();
        output[start..].copy_from_slice(&self.d);
    }
}

/// BC 測試覆寫的 `NextBytes`：重複填入同一段位元組。
struct Repeating(Vec<u8>);

impl Fill for Repeating {
    fn fill(&mut self, output: &mut [u8]) {
        let k = &self.0;
        let length = output.len() as isize;
        let step = k.len() as isize;
        let mut i = 0isize;
        while i < length - step {
            output[i as usize..(i + step) as usize].copy_from_slice(k);
            i += step;
        }
        if i > length {
            let start = (i - step) as usize;
            output[start..].copy_from_slice(&k[..(length - (i - step)) as usize]);
        } else {
            output[i as usize..].copy_from_slice(&k[..(length - i) as usize]);
        }
    }
}

enum Init {
    Fixed { seed: &'static str, zero_two: usize },
    Overridden { x0: u64, c: u64, d: &'static str },
}

struct Case {
    name: &'static str,
    size: u32,
    procedure: u32,
    init: Init,
    k: &'static str,
    x: &'static str,
    p: &'static str,
    q: &'static str,
    r: &'static str,
    s: &'static str,
}

/// 依 BC 的步驟跑一組：產生參數、金鑰對、簽章，比對並驗證。
fn run(case: &Case) {
    let mut init: Box<dyn rand_core::CryptoRng> = match case.init {
        Init::Fixed { seed, zero_two } => {
            let mut data = bytes(seed);
            let mut two = vec![0; zero_two];
            two[zero_two - 1] = 2;
            data.extend(two);
            Box::new(Source(Fixed { data, position: 0 }))
        }
        Init::Overridden { x0, c, d } => {
            let width = if case.procedure == 1 { 4 } else { 8 };
            let encode = |value: u64| value.to_be_bytes()[8 - width..].to_vec();
            Box::new(Source(Overridden {
                first: vec![encode(x0), encode(c)],
                d: bytes(d),
            }))
        }
    };
    let mut generator = Gost3410ParametersGenerator::new();
    generator
        .init(case.size, case.procedure, &mut *init)
        .unwrap();
    let params = generator.generate_parameters().unwrap();
    assert_eq!(params.p(), &integer(case.p), "{}: p", case.name);
    assert_eq!(params.q(), &integer(case.q), "{}: q", case.name);

    let mut key_random = Source(Repeating(bytes(case.x)));
    let mut keys = Gost3410KeyPairGenerator::new();
    keys.init(Gost3410KeyGenerationParams::new(params, &mut key_random))
        .unwrap();
    let (public_key, private_key) = keys.generate_key_pair().unwrap();

    let message = bytes(HASH_MESSAGE);
    let mut signer = Gost3410Signer::new(Source(Repeating(bytes(case.k))));
    signer.init(&private_key).unwrap();
    let (r, s) = signer.generate_signature(&message).unwrap();
    assert_eq!(r, integer(case.r), "{}: r", case.name);
    assert_eq!(s, integer(case.s), "{}: s", case.name);

    let mut verifier = Gost3410Signer::new(rand::rng());
    verifier.init(&public_key).unwrap();
    assert!(
        verifier.verify_signature(&message, &r, &s).unwrap(),
        "{}",
        case.name
    );
    assert!(
        !verifier.verify_signature(&message[1..], &r, &s).unwrap(),
        "{}",
        case.name
    );
}

const CASES: [Case; 11] = [
    Case {
        name: "Gost3410_TEST1_512",
        size: 512,
        procedure: 1,
        init: Init::Fixed {
            seed: "00005EC900007341",
            zero_two: 64,
        },
        k: "90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A",
        x: "3036314538303830343630454235324435324234314132373832433138443046",
        p: "EE8172AE8996608FB69359B89EB82A69854510E2977A4D63BC97322CE5DC3386EA0A12B343E9190F23177539845839786BB0C345D165976EF2195EC9B1C379E3",
        q: "98915E7EC8265EDFCDA31E88F24809DDB064BDC7285DD50D7289F0AC6F49DD2D",
        r: "3e5f895e276d81d2d52c0763270a458157b784c57abdbd807bc44fd43a32ac06",
        s: "3f0dd5d4400d47c08e4ce505ff7434b6dbf729592e37c74856dab85115a60955",
    },
    Case {
        name: "Gost3410_TEST2_512",
        size: 512,
        procedure: 2,
        init: Init::Fixed {
            seed: "000000003DFC46F1000000000000000D",
            zero_two: 64,
        },
        k: "90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A",
        x: "3036314538303830343630454235324435324234314132373832433138443046",
        p: "8b08eb135af966aab39df294538580c7da26765d6d38d30cf1c06aae0d1228c3316a0e29198460fad2b19dc381c15c888c6dfd0fc2c565abb0bf1faff9518f85",
        q: "931a58fb6f0dcdf2fe7549bc3f19f4724b56898f7f921a076601edb18c93dc75",
        r: "7c07c8cf035c2a1cb2b7fae5807ac7cd623dfca7a1a68f6d858317822f1ea00d",
        s: "7e9e036a6ff87dbf9b004818252b1f6fc310bdd4d17cb8c37d9c36c7884de60c",
    },
    Case {
        name: "Gost3410_TEST1_1024",
        size: 1024,
        procedure: 1,
        init: Init::Overridden {
            x0: 0xA565,
            c: 0x538B,
            d: "02",
        },
        k: "90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A",
        x: "3036314538303830343630454235324435324234314132373832433138443046",
        p: "ab8f37938356529e871514c1f48c5cbce77b2f4fc9a2673ac2c1653da8984090c0ac73775159a26bef59909d4c9846631270e16653a6234668f2a52a01a39b921490e694c0f104b58d2e14970fccb478f98d01e975a1028b9536d912de5236d2dd2fc396b77153594d4178780e5f16f718471e2111c8ce64a7d7e196fa57142d",
        q: "bcc02ca0ce4f0753ec16105ee5d530aa00d39f3171842ab2c334a26b5f576e0f",
        r: "a8790aabbd5a998ff524bad048ac69cd1faff2dab048265c8d60d1471c44a9ee",
        s: "30df5ba32ac77170b9632559bef7d37620017756dff3fea1088b4267db0944b8",
    },
    Case {
        name: "Gost3410_TEST2_1024",
        size: 1024,
        procedure: 2,
        init: Init::Overridden {
            x0: 0x3DFC46F1,
            c: 0xD,
            d: "02",
        },
        k: "90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A",
        x: "3036314538303830343630454235324435324234314132373832433138443046",
        p: "e2c4191c4b5f222f9ac2732562f6d9b4f18e7fb67a290ea1e03d750f0b9806755fc730d975bf3faa606d05c218b35a6c3706919aab92e0c58b1de4531c8fa8e7af43c2bff016251e21b2870897f6a27ac4450bca235a5b748ad386e4a0e4dfcb09152435abcfe48bd0b126a8122c7382f285a9864615c66decddf6afd355dfb7",
        q: "931a58fb6f0dcdf2fe7549bc3f19f4724b56898f7f921a076601edb18c93dc75",
        r: "81d69a192e9c7ac21fc07da41bd07e230ba6a94eb9f3c1fd104c7bd976733ca5",
        s: "315c879c8414f35feb4deb15e7cc0278c48e6ca1596325d6959338d860b0c47a",
    },
    Case {
        name: "Gost3410_AParam",
        size: 1024,
        procedure: 2,
        init: Init::Overridden {
            x0: 0x520874F5,
            c: 0xEE39ADB3,
            d: "02",
        },
        k: "90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A",
        x: "3036314538303830343630454235324435324234314132373832433138443046",
        p: "b4e25efb018e3c8b87505e2a67553c5edc56c2914b7e4f89d23f03f03377e70a2903489dd60e78418d3d851edb5317c4871e40b04228c3b7902963c4b7d85d52b9aa88f2afdbeb28da8869d6df846a1d98924e925561bd69300b9ddd05d247b5922d967cbb02671881c57d10e5ef72d3e6dad4223dc82aa1f7d0294651a480df",
        q: "972432a437178b30bd96195b773789ab2fff15594b176dd175b63256ee5af2cf",
        r: "64a8856628e5669d85f62cd763dd4a99bc56d33dc0e1859122855d141e9e4774",
        s: "319ebac97092b288d469a4b988248794f60c865bc97858d9a3135c6d1a1bf2dd",
    },
    Case {
        name: "Gost3410_BParam",
        size: 1024,
        procedure: 2,
        init: Init::Overridden {
            x0: 0x5B977CDB,
            c: 0x6E9692DD,
            d: "bc3cbbdb7e6f848286e19ad9a27a8e297e5b71c53dd974cdf60f937356df69cbc97a300ccc71685c553046147f11568c4fddf363d9d886438345a62c3b75963d6546adfabf31b31290d12cae65ecb8309ef66782",
        },
        k: "90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A",
        x: "3036314538303830343630454235324435324234314132373832433138443046",
        p: "c6971fc57524b30c9018c5e621de15499736854f56a6f8aee65a7a404632b3540f09020f67f04dc2e6783b141dceffd21a703035b7d0187c6e12cb4229922bafdb2225b73e6b23a0de36e20047065aea000c1a374283d0ad8dc1981e3995f0bb8c72526041fcb98ae6163e1e71a669d8364e9c4c3188f673c5f8ee6fadb41abf",
        q: "b09d634c10899cd7d4c3a7657403e05810b07c61a688bab2c37f475e308b0607",
        r: "860d82c60e9502cd00c0e9e1f6563feafec304801974d745c5e02079946f729e",
        s: "7ef49264ef022801aaa03033cd97915235fbab4c823ed936b0f360c22114688a",
    },
    Case {
        name: "Gost3410_CParam",
        size: 1024,
        procedure: 2,
        init: Init::Overridden {
            x0: 0x43848744,
            c: 0xB50A826D,
            d: "7F575E8194BC5BDF",
        },
        k: "90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A",
        x: "3036314538303830343630454235324435324234314132373832433138443046",
        p: "9d88e6d7fe3313bd2e745c7cdd2ab9ee4af3c8899e847de74a33783ea68bc30588ba1f738c6aaf8ab350531f1854c3837cc3c860ffd7e2e106c3f63b3d8a4c034ce73942a6c3d585b599cf695ed7a3c4a93b2b947b7157bb1a1c043ab41ec8566c6145e938a611906de0d32e562494569d7e999a0dda5c879bdd91fe124df1e9",
        q: "fadd197abd19a1b4653eecf7eca4d6a22b1f7f893b641f901641fbb555354faf",
        r: "4deb95a0b35e7ed7edebe9bef5a0f93739e16b7ff27fe794d989d0c13159cfbc",
        s: "e1d0d30345c24cfeb33efde3deee5fbbda78ddc822b719d860cd0ba1fb6bd43b",
    },
    Case {
        name: "Gost3410_DParam",
        size: 1024,
        procedure: 2,
        init: Init::Overridden {
            x0: 0x13DA8B9D,
            c: 0xA0E9DE4B,
            d: "41ab97857f42614355d32db0b1069f109a4da283676c7c53a68185b4",
        },
        k: "90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A",
        x: "3036314538303830343630454235324435324234314132373832433138443046",
        p: "80f102d32b0fd167d069c27a307adad2c466091904dbaa55d5b8cc7026f2f7a1919b890cb652c40e054e1e9306735b43d7b279eddf9102001cd9e1a831fe8a163eed89ab07cf2abe8242ac9dedddbf98d62cddd1ea4f5f15d3a42a6677bdd293b24260c0f27c0f1d15948614d567b66fa902baa11a69ae3bceadbb83e399c9b5",
        q: "f0f544c418aac234f683f033511b65c21651a6078bda2d69bb9f732867502149",
        r: "712592d285b792e33b8a9a11e8e6c4f512ddf0042972bbfd1abb0a93e8fc6f54",
        s: "2cf26758321258b130d5612111339f09ceb8668241f3482e38baa56529963f07",
    },
    Case {
        name: "Gost3410_AExParam",
        size: 1024,
        procedure: 2,
        init: Init::Overridden {
            x0: 0xD05E9F14,
            c: 0x46304C5F,
            d: "35ab875399cda33c146ca629660e5a5e5c07714ca326db032dd6751995cdb90a612b9228932d8302704ec24a5def7739c5813d83",
        },
        k: "90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A",
        x: "3036314538303830343630454235324435324234314132373832433138443046",
        p: "ca3b3f2eee9fd46317d49595a9e7518e6c63d8f4eb4d22d10d28af0b8839f079f8289e603b03530784b9bb5a1e76859e4850c670c7b71c0df84ca3e0d6c177fe9f78a9d8433230a883cd82a2b2b5c7a3306980278570cdb79bf01074a69c9623348824b0c53791d53c6a78cab69e1cfb28368611a397f50f541e16db348dbe5f",
        q: "cae4d85f80c147704b0ca48e85fb00a9057aa4acc44668e17f1996d7152690d9",
        r: "90892707282f433398488f19d31ac48523a8e2ded68944e0da91c6895ee7045e",
        s: "3be4620ee88f1ee8f9dd63c7d145b7e554839feeca125049118262ea4651e9de",
    },
    Case {
        name: "Gost3410_BExParam",
        size: 1024,
        procedure: 2,
        init: Init::Overridden {
            x0: 0x7A007804,
            c: 0xD31A4FF7,
            d: "7ec123d161477762838c2bea9dbdf33074af6d41d108a066a1e7a07ab3048de2",
        },
        k: "90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A",
        x: "3036314538303830343630454235324435324234314132373832433138443046",
        p: "9286dbda91eccfc3060aa5598318e2a639f5ba90a4ca656157b2673fb191cd0589ee05f4cef1bd13508408271458c30851ce7a4ef534742bfb11f4743c8f787b11193ba304c0e6bca25701bf88af1cb9b8fd4711d89f88e32b37d95316541bf1e5dbb4989b3df13659b88c0f97a3c1087b9f2d5317d557dcd4afc6d0a754e279",
        q: "c966e9b3b8b7cdd82ff0f83af87036c38f42238ec50a876cd390e43d67b6013f",
        r: "8f79a582513df84dc247bcb624340cc0e5a34c4324a20ce7fe3ab8ff38a9db71",
        s: "7508d22fd6cbb45efd438cb875e43f137247088d0f54b29a7c91f68a65b5fa85",
    },
    Case {
        name: "Gost3410_CExParam",
        size: 1024,
        procedure: 2,
        init: Init::Overridden {
            x0: 0x162AB910,
            c: 0x93F828D3,
            d: "ca82cce78a738bc46f103d53b9bf809745ec845e4f6da462606c51f60ecf302e31204b81",
        },
        k: "90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A",
        x: "3036314538303830343630454235324435324234314132373832433138443046",
        p: "b194036ace14139d36d64295ae6c50fc4b7d65d8b340711366ca93f383653908ee637be428051d86612670ad7b402c09b820fa77d9da29c8111a8496da6c261a53ed252e4d8a69a20376e6addb3bdcd331749a491a184b8fda6d84c31cf05f9119b5ed35246ea4562d85928ba1136a8d0e5a7e5c764ba8902029a1336c631a1d",
        q: "96120477df0f3896628e6f4a88d83c93204c210ff262bccb7dae450355125259",
        r: "169fdb2dc09f690b71332432bfec806042e258fa9a21dafe73c6abfbc71407d9",
        s: "9002551808ae40d19f6f31fb67e4563101243cf07cffd5f2f8ff4c537b0c9866",
    },
];

#[test]
fn the_512_bit_cases_of_both_procedures_match_bouncy_castle() {
    run(&CASES[0]);
    run(&CASES[1]);
}

#[test]
fn the_1024_bit_test_cases_of_both_procedures_match_bouncy_castle() {
    run(&CASES[2]);
    run(&CASES[3]);
}

#[test]
#[ignore = "debug 建置下共約 30 秒"]
fn the_other_1024_bit_cases_match_bouncy_castle() {
    for case in &CASES[4..] {
        run(case);
    }
}
