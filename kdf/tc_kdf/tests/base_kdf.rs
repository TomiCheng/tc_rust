use core::convert::Infallible;

use tc_digest::{Digest, TryDigest};
use tc_kdf::kdf::{Kdf1, Kdf2, KdfParamsRef};
use tc_kdf::{Kdf, KdfError, KdfInit};
use tc_sha::{Sha1Digest, Sha256Digest};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// BC 的 `ShortenedDigest(new Sha256Digest(), 20)`：只取 SHA-256 的前 20 bytes。
struct Sha256Shortened20(Sha256Digest);

impl TryDigest for Sha256Shortened20 {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        20
    }

    fn byte_length(&self) -> usize {
        self.0.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Infallible> {
        self.0.update(input);
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Infallible> {
        let mut full = [0; 32];
        self.0.do_final(&mut full);
        output[..20].copy_from_slice(&full[..20]);
        Ok(20)
    }

    fn try_reset(&mut self) -> Result<(), Infallible> {
        self.0.reset();
        Ok(())
    }
}

fn shortened() -> Sha256Shortened20 {
    Sha256Shortened20(Sha256Digest::new())
}

fn derive<K>(kdf: &mut K, seed: &[u8], len: usize) -> Vec<u8>
where
    K: Kdf + for<'a> KdfInit<KdfParamsRef<'a>>,
{
    kdf.init(&KdfParamsRef::new(seed)).ok().unwrap();
    let mut output = vec![0; len];
    assert_eq!(kdf.generate_bytes(&mut output).ok(), Some(len));
    output
}

const SEED_1: &str = "d6e168c5f256a2dcff7ef12facd390f393c7a88d";
const SEED_2: &str = "032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4";

#[test]
fn kdf1_matches_the_iso_18033_vectors() {
    let mask_1 = "0742ba966813af75536bb6149cc44fc256fd6406df79665bc31dc5a62f70535e52c53015b9d37d412ff3c1193439599e1b628774c50d9ccb78d82c425e4521ee47b8c36a4bcffe8b8112a89312fc04420a39de99223890e74ce10378bc515a212b97b8a6447ba6a8870278";
    let mask_2 = "5f8de105b5e96b2e490ddecbd147dd1def7e3b8e0e6a26eb7b956ccb8b3bdc1ca975bc57c3989e8fbad31a224655d800c46954840ff32052cdf0d640562bdfadfa263cfccf3c52b29f2af4a1869959bc77f854cf15bd7a25192985a842dbff8e13efee5b7e7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837eea4e0a2f04";
    let mask_3 = "09e2decf2a6e1666c2f6071ff4298305e2643fd510a2403db42a8743cb989de86e668d168cbe604611ac179f819a3d18412e9eb45668f2923c087c12fee0c5a0d2a8aa70185401fbbd99379ec76c663e875a60b4aacb1319fa11c3365a8b79a44669f26fb555c80391847b05eca1cb5cf8c2d531448d33fbaca19f6410ee1fcb";

    let mut kdf = Kdf1::new(shortened());
    assert_eq!(
        derive(&mut kdf, &hex(SEED_1), mask_1.len() / 2),
        hex(mask_1)
    );
    assert_eq!(
        derive(&mut kdf, &hex(SEED_2), mask_3.len() / 2),
        hex(mask_3)
    );
    let mut kdf = Kdf1::new(Sha1Digest::new());
    assert_eq!(
        derive(&mut kdf, &hex(SEED_2), mask_2.len() / 2),
        hex(mask_2)
    );
}

#[test]
fn kdf2_matches_the_bc_vectors() {
    let mask_1 = "df79665bc31dc5a62f70535e52c53015b9d37d412ff3c1193439599e1b628774c50d9ccb78d82c425e4521ee47b8c36a4bcffe8b8112a89312fc04420a39de99223890e74ce10378bc515a212b97b8a6447ba6a8870278f0262727ca041fa1aa9f7b5d1cf7f308232fe861";
    let mask_2 = "10a2403db42a8743cb989de86e668d168cbe604611ac179f819a3d18412e9eb45668f2923c087c12fee0c5a0d2a8aa70185401fbbd99379ec76c663e875a60b4aacb1319fa11c3365a8b79a44669f26fb555c80391847b05eca1cb5cf8c2d531448d33fbaca19f6410ee1fcb260892670e0814c348664f6a7248aaf998a3acc6";
    let adjusted_mask_2 = "10a2403db42a8743cb989de86e668d168cbe6046e23ff26f741e87949a3bba1311ac179f819a3d18412e9eb45668f2923c087c1299005f8d5fd42ca257bc93e8fee0c5a0d2a8aa70185401fbbd99379ec76c663e9a29d0b70f3fe261a59cdc24875a60b4aacb1319fa11c3365a8b79a44669f26fba933d012db213d7e3b16349";
    let sha1_mask = "0e6a26eb7b956ccb8b3bdc1ca975bc57c3989e8fbad31a224655d800c46954840ff32052cdf0d640562bdfadfa263cfccf3c52b29f2af4a1869959bc77f854cf15bd7a25192985a842dbff8e13efee5b7e7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837eea4e0a2f04b53ca8f50fb31225c1be2d0126c8c7a4753b0807";

    let mut kdf = Kdf2::new(shortened());
    assert_eq!(
        derive(&mut kdf, &hex(SEED_1), mask_1.len() / 2),
        hex(mask_1)
    );
    assert_eq!(
        derive(&mut kdf, &hex(SEED_2), mask_2.len() / 2),
        hex(mask_2)
    );

    let mut kdf = Kdf2::new(Sha256Digest::new());
    assert_eq!(
        derive(&mut kdf, &hex(SEED_2), adjusted_mask_2.len() / 2),
        hex(adjusted_mask_2)
    );

    let mut kdf = Kdf2::new(Sha1Digest::new());
    for (seed, mask) in [
        (SEED_2, sha1_mask),
        (
            "CA7C0F8C3FFA87A96E1B74AC8E6AF594347BB40A",
            "744AB703F5BC082E59185F6D049D2D367DB245C2",
        ),
        (
            "0499B502FC8B5BAFB0F4047E731D1F9FD8CD0D8881",
            "03C62280C894E103C680B13CD4B4AE740A5EF0C72547292F82DC6B1777F47D63BA9D1EA732DBF386",
        ),
    ] {
        assert_eq!(
            derive(&mut kdf, &hex(seed), mask.len() / 2),
            hex(mask),
            "{seed}"
        );
    }
}

#[test]
fn the_iv_is_hashed_after_the_counter() {
    let (secret, iv) = (b"shared secret", b"context");
    let mut kdf = Kdf2::new(Sha256Digest::new());
    kdf.init(&KdfParamsRef::with_iv(secret, iv)).ok().unwrap();
    let mut output = [0; 32];
    kdf.generate_bytes(&mut output).unwrap();

    let mut digest = Sha256Digest::new();
    digest.update(secret);
    digest.update(&1u32.to_be_bytes());
    digest.update(iv);
    let mut expected = [0; 32];
    digest.do_final(&mut expected);
    assert_eq!(output, expected);
}

#[test]
fn every_call_starts_over_from_the_first_block() {
    let mut kdf = Kdf2::new(Sha256Digest::new());
    let first = derive(&mut kdf, b"secret", 40);
    let mut second = [0; 40];
    kdf.generate_bytes(&mut second).unwrap();
    assert_eq!(first, second);
}

#[test]
fn generating_before_init_fails() {
    let mut kdf = Kdf2::new(Sha256Digest::new());
    assert_eq!(
        kdf.generate_bytes(&mut [0; 16]),
        Err(KdfError::NotInitialised)
    );
}
