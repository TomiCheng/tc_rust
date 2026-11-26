use tc_bigint::PaddedBigUint;

use crate::Gost3410Parameters;

// BC 的 Gost3410NamedParameters 以十進位字串保存 p、q 與 a。
fn domain(p: &str, q: &str, a: &str) -> Gost3410Parameters {
    Gost3410Parameters::new(
        p.parse::<PaddedBigUint>().expect("十進位模數 p"),
        q.parse::<PaddedBigUint>().expect("十進位子群階 q"),
        a.parse::<PaddedBigUint>().expect("十進位生成元 a"),
    )
}

/// BC 的 `GostR3410-94-CryptoPro-A`（OID `1.2.643.2.2.32.2`）。
/// 變動時間：只有公開常數。
pub fn cryptopro_a() -> Gost3410Parameters {
    // GOST3410NamedParameters.cs 第 14 至 16 行。
    domain(
        "127021248288932417465907042777176443525787653508916535812817507265705031\
         260985098497423188333483401180925999995120988934130659205614996724254121\
         049274349357074920312769561451689224110579311248812610229678534638401693\
         520013288995000362260684222750813532307004517341633685004541062586971416\
         883686778842537820383",
        "683631961449557007844441656118272528951021708887614420550950512875503140\
         83023",
        "100997906755055304772081815535925224869841082572053457874823515875577147\
         990529272777244152852699298796483356699682842027972896052747173175480590\
         485607134746852141928680912561502802222185647539190902656116367847270145\
         019066794290930185446216399730872221732889830323194097355403213400972588\
         322876850946740663962",
    )
}

/// BC 的 `GostR3410-94-CryptoPro-B`（OID `1.2.643.2.2.32.3`）。
/// 變動時間：只有公開常數。
pub fn cryptopro_b() -> Gost3410Parameters {
    // GOST3410NamedParameters.cs 第 31 至 33 行。
    domain(
        "139454871199115825601409655107690713107041707059928031797758001454375765\
         357722984094124368522288239833039114681648076688236921220737322672160740\
         747771700911134550432053804647694904686120113087816240740184800477047157\
         336662926249423571248823968542221753660143391485680840520336859458494803\
         187341288580489525163",
        "798851416634109768976271189357563237473079519165076397583004726923388735\
         33959",
        "429418261486158041438734477379555023926723459686071430667981129940894712\
         314200270603852166995638487199576572848148989097707594626134376694563648\
         827303708389347910808359326479767786019153434744009610342313166725786869\
         204821949328786333602033847970926843422476210557602350161326147806527610\
         28509445403338652341",
    )
}

/// BC 的 `GostR3410-94-CryptoPro-XchA`（OID `1.2.643.2.2.33.1`）。
/// 變動時間：只有公開常數。
pub fn cryptopro_xch_a() -> Gost3410Parameters {
    // GOST3410NamedParameters.cs 第 52 至 54 行。
    domain(
        "142011741597563481196368286022318089743276138395243738762872573441927459\
         393512718973631166078467600360848946623567625795282774719212241929071046\
         134208380636394084512691828894000571524625445295769349356752728956831541\
         775441763139384457191755096847107846595662547942312293338483924514339614\
         727760681880609734239",
        "917715298965546059455881490183827502172968583935207241727433257254743749\
         79801",
        "133531813272720673433859519948319001217942375967847486899482359599369642\
         528734712461590403327731821410328012529253871914788598993103310567744136\
         196364803064721377826656898686468463277710150809401182608770201615324990\
         468332931294920912776241137878030224355746606283971659376426832674269780\
         880061631528163475887",
    )
}

#[cfg(test)]
mod tests {
    use super::{Gost3410Parameters, cryptopro_a, cryptopro_b, cryptopro_xch_a};
    use crate::{Gost3410KeyGenerationParams, Gost3410KeyPairGenerator, Gost3410Signer};
    use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
    use tc_bigint::{ArrayEncoding, BigUint};
    use tc_dsa::Gost3410DigestSigner;
    use tc_gost3411::Gost3411Digest;
    use tc_modular::{ModPow, NonZero};
    use tc_signer::{Signer, SignerInit};

    type NamedDomain = (&'static str, fn() -> Gost3410Parameters);

    const DOMAINS: [NamedDomain; 3] = [
        ("CryptoPro-A", cryptopro_a),
        ("CryptoPro-B", cryptopro_b),
        ("CryptoPro-XchA", cryptopro_xch_a),
    ];

    #[test]
    fn every_named_domain_has_the_expected_sizes_and_subgroup_generator() {
        for (name, make_domain) in DOMAINS {
            let domain = make_domain();
            domain.validate().expect(name);
            assert_eq!(domain.p().bits(), 1024, "{name}");
            assert_eq!(domain.q().bits(), 256, "{name}");
            let modulus = NonZero::new(BigUint::from(domain.p().clone())).expect(name);
            let a = BigUint::from(domain.a().clone());
            let q = BigUint::from(domain.q().clone());
            assert_eq!(a.mod_pow(&q, &modulus), BigUint::from(1u8), "{name}");
        }
    }

    #[test]
    fn every_named_domain_matches_the_order_in_rfc_4357() {
        // RFC 4357 §11.3 的 INTEGER q，以無號大端序比較。
        for ((name, make_domain), expected) in DOMAINS.into_iter().zip([
            "972432A437178B30BD96195B773789AB2FFF15594B176DD175B63256EE5AF2CF",
            "B09D634C10899CD7D4C3A7657403E05810B07C61A688BAB2C37F475E308B0607",
            "CAE4D85F80C147704B0CA48E85FB00A9057AA4ACC44668E17F1996D7152690D9",
        ]) {
            let bytes: alloc::vec::Vec<_> = expected
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let pair = core::str::from_utf8(pair).expect("十六進位常數");
                    u8::from_str_radix(pair, 16).expect("十六進位位元組")
                })
                .collect();
            let domain = make_domain();
            let Ok(order) = tc_bigint::PaddedBigUint::from_be(&bytes);
            assert_eq!(*domain.q(), order, "{name}");
        }
    }

    #[test]
    fn every_named_domain_generates_keys_that_sign_and_verify_a_message() {
        for (name, make_domain) in DOMAINS {
            let mut generator = Gost3410KeyPairGenerator::new(rand::rng());
            generator
                .init(&Gost3410KeyGenerationParams::new(make_domain()))
                .expect(name);
            let (public, private) = generator.generate_key_pair().expect(name);

            let mut signer =
                Gost3410DigestSigner::new(Gost3410Signer::new(rand::rng()), Gost3411Digest::new());
            signer.init(&private).expect(name);
            signer.update(b"hello").expect(name);
            let mut signature = alloc::vec![0; signer.max_signature_size()];
            let length = signer.generate_signature(&mut signature).expect(name);

            public.validate().expect(name);
            let mut verifier =
                Gost3410DigestSigner::new(Gost3410Signer::new(rand::rng()), Gost3411Digest::new());
            verifier.init(&public).expect(name);
            verifier.update(b"hello").expect(name);
            assert!(
                verifier.verify_signature(&signature[..length]).expect(name),
                "{name}"
            );
        }
    }
}
