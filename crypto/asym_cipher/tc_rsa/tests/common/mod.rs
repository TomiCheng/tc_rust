//! The key the integration tests and the benches share, and the ways in
//! and out of each kind of integer.

#![allow(dead_code)]

/// The first key of Wycheproof's `rsa_pkcs1_2048_test.json`, from C2SP,
/// with its CRT values; the public exponent is 65537.
pub const N: &str = concat!(
    "b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc",
    "3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742",
    "bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbe",
    "b019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140c",
    "cb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b1",
    "8098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4",
    "856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d",
    "524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d",
);
pub const D: &str = concat!(
    "1a502d0eea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8c",
    "eb066c62d727e32d26c58137329f89d3195325b795264c195d85472f7507dbd0",
    "961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131",
    "c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9",
    "f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6c",
    "b8bc88ef0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d46",
    "7069ca660887c987766349fcc43460b4aa516bce079edd87ba164307b752c277",
    "ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd",
);
pub const P: &str = concat!(
    "ec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4fb71bd4dd8561244",
    "98aaeba983d7ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3",
    "aa15e74a1768778093be0edd4a8d09b2def6dc9b67ff85764625c2e19236db4c",
    "401ce30a2572d3ecb4f969b7ad19c522c02d774465676e1a3776c54d6248348b",
);
pub const Q: &str = concat!(
    "c2742abcd9897bd4b0b671f973fc82a8f84abf5705ff88dd41948623afe9dca6",
    "0dc6543390767feaebeb539576ee8bfa61b5fcbca94a7cef75a09150c540fa96",
    "94dd8004ad23718c889049219369c99f4458d4afc148f6f07df87324a96d9cf7",
    "b385dd8622414a1832f9f29446f050c2d5a6407649dc41ab70e23b3dcc22c987",
);
pub const DP: &str = concat!(
    "96a9798d250263400bb6277342881627e07cecdf91187b01b89ff47314188a7c",
    "20fb24800156d2c85d5666e8df6ceff9f9804ddfad80ff5767de56ecc029c72b",
    "f6c717df9f64daafc29acf9dc7908f9a0ad67e20e8949936ccba18d021a2c4fe",
    "bb04349a2b2047c4901385b6e5d0c691d118b33f81802b32ac272ef09e42fad5",
);
pub const DQ: &str = concat!(
    "0554f41b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9e2dab6",
    "fee7b2455bafb42037e9d2f7e533f348a147412fd72080be7c2633f5d802c91c",
    "39e6bcece3e675e59995033c55737020dad9e8b30d04b828adfb9304ad54a11a",
    "35a4f50709876ac5b118236ba76a4d7c9a291dd9607b169de1d182385691999f",
);
pub const Q_INV: &str = concat!(
    "1c640189d9bfe8c623833210a76c420c6f44e5d760e259916cec2ae2b1564569",
    "60fd95e2747660c389562250f055049cfab7e5c3039549384a7a2aaeb1c824d3",
    "af709482a8cf9b587022a00b1f0722db50f33cb26dc20dd2245d5265df61ee29",
    "83c938c2167dcee121fc4b4479c237e728cf633ab60a8c0ecd04fce7e3baa559",
);

/// `text`, in hexadecimal, as big-endian bytes.
pub fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// A block below the Wycheproof modulus, of its full input block when
/// encrypting.
pub const BLOCK: [u8; 255] = [0x5a; 255];
