use crate::X962F2mNamedCurve;
use crate::hex::hex;
use crate::x962_f2m_named_curve::Taps;

/// X9.62 c2pnb163v1，GF(2^163)，餘因子 2。
pub const C2PNB163V1: X962F2mNamedCurve<21> = X962F2mNamedCurve {
    m: 163,
    taps: Taps::Pentanomial(1, 2, 8),
    a: hex("072546b5435234a422e0789675f432c89435de5242"),
    b: hex("00c9517d06d5240d3cff38c74b20b6cd4d6f9dd4d9"),
    order: hex("0400000000000000000001e60fc8821cc74daeafc1"),
    cofactor: 2,
    gx: hex("07af69989546103d79329fcc3d74880f33bbe803cb"),
    gy: hex("01ec23211b5966adea1d3f87f7ea5848aef0b7ca9f"),
};

/// X9.62 c2pnb163v2，GF(2^163)，餘因子 2。
pub const C2PNB163V2: X962F2mNamedCurve<21> = X962F2mNamedCurve {
    m: 163,
    taps: Taps::Pentanomial(1, 2, 8),
    a: hex("0108b39e77c4b108bed981ed0e890e117c511cf072"),
    b: hex("0667aceb38af4e488c407433ffae4f1c811638df20"),
    order: hex("03fffffffffffffffffffdf64de1151adbb78f10a7"),
    cofactor: 2,
    gx: hex("0024266e4eb5106d0a964d92c4860e2671db9b6cc5"),
    gy: hex("079f684ddf6684c5cd258b3890021b2386dfd19fc5"),
};

/// X9.62 c2pnb163v3，GF(2^163)，餘因子 2。
pub const C2PNB163V3: X962F2mNamedCurve<21> = X962F2mNamedCurve {
    m: 163,
    taps: Taps::Pentanomial(1, 2, 8),
    a: hex("07a526c63d3e25a256a007699f5447e32ae456b50e"),
    b: hex("03f7061798eb99e238fd6f1bf95b48feeb4854252b"),
    order: hex("03fffffffffffffffffffe1aee140f110aff961309"),
    cofactor: 2,
    gx: hex("02f9f87b7c574d0bdecf8a22e6524775f98cdebdcb"),
    gy: hex("05b935590c155e17ea48eb3ff3718b893df59a05d0"),
};

/// X9.62 c2pnb176w1，GF(2^176)，餘因子 65390。
pub const C2PNB176W1: X962F2mNamedCurve<22> = X962F2mNamedCurve {
    m: 176,
    taps: Taps::Pentanomial(1, 2, 43),
    a: hex("e4e6db2995065c407d9d39b8d0967b96704ba8e9c90b"),
    b: hex("5dda470abe6414de8ec133ae28e9bbd7fcec0ae0fff2"),
    order: hex("00010092537397eca4f6145799d62b0a19ce06fe26ad"),
    cofactor: 65390,
    gx: hex("8d16c2866798b600f9f08bb4a8e860f3298ce04a5798"),
    gy: hex("6fa4539c2dadddd6bab5167d61b436e1d92bb16a562c"),
};

/// X9.62 c2tnb191v1，GF(2^191)，餘因子 2。
pub const C2TNB191V1: X962F2mNamedCurve<24> = X962F2mNamedCurve {
    m: 191,
    taps: Taps::Trinomial(9),
    a: hex("2866537b676752636a68f56554e12640276b649ef7526267"),
    b: hex("2e45ef571f00786f67b0081b9495a3d95462f5de0aa185ec"),
    order: hex("40000000000000000000000004a20e90c39067c893bbb9a5"),
    cofactor: 2,
    gx: hex("36b3daf8a23206f9c4f299d7b21a9c369137f2c84ae1aa0d"),
    gy: hex("765be73433b3f95e332932e70ea245ca2418ea0ef98018fb"),
};

/// X9.62 c2tnb191v2，GF(2^191)，餘因子 4。
pub const C2TNB191V2: X962F2mNamedCurve<24> = X962F2mNamedCurve {
    m: 191,
    taps: Taps::Trinomial(9),
    a: hex("401028774d7777c7b7666d1366ea432071274f89ff01e718"),
    b: hex("0620048d28bcbd03b6249c99182b7c8cd19700c362c46a01"),
    order: hex("20000000000000000000000050508cb89f652824e06b8173"),
    cofactor: 4,
    gx: hex("3809b2b7cc1b28cc5a87926aad83fd28789e81e2c9e3bf10"),
    gy: hex("17434386626d14f3dbf01760d9213a3e1cf37aec437d668a"),
};

/// X9.62 c2tnb191v3，GF(2^191)，餘因子 6。
pub const C2TNB191V3: X962F2mNamedCurve<24> = X962F2mNamedCurve {
    m: 191,
    taps: Taps::Trinomial(9),
    a: hex("6c01074756099122221056911c77d77e77a777e7e7e77fcb"),
    b: hex("71fe1af926cf847989efef8db459f66394d90f32ad3f15e8"),
    order: hex("155555555555555555555555610c0b196812bfb6288a3ea3"),
    cofactor: 6,
    gx: hex("375d4ce24fde434489de8746e71786015009e66e38a926dd"),
    gy: hex("545a39176196575d985999366e6ad34ce0a77cd7127b06be"),
};

/// X9.62 c2pnb208w1，GF(2^208)，餘因子 65096。
pub const C2PNB208W1: X962F2mNamedCurve<26> = X962F2mNamedCurve {
    m: 208,
    taps: Taps::Pentanomial(1, 2, 83),
    a: hex("0000000000000000000000000000000000000000000000000000"),
    b: hex("c8619ed45a62e6212e1160349e2bfa844439fafc2a3fd1638f9e"),
    order: hex("000101baf95c9723c57b6c21da2eff2d5ed588bdd5717e212f9d"),
    cofactor: 65096,
    gx: hex("89fdfbe4abe193df9559ecf07ac0ce78554e2784eb8c1ed1a57a"),
    gy: hex("0f55b51a06e78e9ac38a035ff520d8b01781beb1a6bb08617de3"),
};

/// X9.62 c2tnb239v1，GF(2^239)，餘因子 4。
pub const C2TNB239V1: X962F2mNamedCurve<30> = X962F2mNamedCurve {
    m: 239,
    taps: Taps::Trinomial(36),
    a: hex("32010857077c5431123a46b808906756f543423e8d27877578125778ac76"),
    b: hex("790408f2eedaf392b012edefb3392f30f4327c0ca3f31fc383c422aa8c16"),
    order: hex("2000000000000000000000000000000f4d42ffe1492a4993f1cad666e447"),
    cofactor: 4,
    gx: hex("57927098fa932e7c0a96d3fd5b706ef7e5f5c156e16b7e7c86038552e91d"),
    gy: hex("61d8ee5077c33fecf6f1a16b268de469c3c7744ea9a971649fc7a9616305"),
};

/// X9.62 c2tnb239v2，GF(2^239)，餘因子 6。
pub const C2TNB239V2: X962F2mNamedCurve<30> = X962F2mNamedCurve {
    m: 239,
    taps: Taps::Trinomial(36),
    a: hex("4230017757a767fae42398569b746325d45313af0766266479b75654e65f"),
    b: hex("5037ea654196cff0cd82b2c14a2fcf2e3ff8775285b545722f03eacdb74b"),
    order: hex("1555555555555555555555555555553c6f2885259c31e3fcdf154624522d"),
    cofactor: 6,
    gx: hex("28f9d04e900069c8dc47a08534fe76d2b900b7d7ef31f5709f200c4ca205"),
    gy: hex("5667334c45aff3b5a03bad9dd75e2c71a99362567d5453f7fa6e227ec833"),
};

/// X9.62 c2tnb239v3，GF(2^239)，餘因子 10。
pub const C2TNB239V3: X962F2mNamedCurve<30> = X962F2mNamedCurve {
    m: 239,
    taps: Taps::Trinomial(36),
    a: hex("01238774666a67766d6676f778e676b66999176666e687666d8766c66a9f"),
    b: hex("6a941977ba9f6a435199acfc51067ed587f519c5ecb541b8e44111de1d40"),
    order: hex("0cccccccccccccccccccccccccccccac4912d2d9df903ef9888b8a0e4cff"),
    cofactor: 10,
    gx: hex("70f6e9d04d289c4e89913ce3530bfde903977d42b146d539bf1bde4e9c92"),
    gy: hex("2e5a0eaf6e5e1305b9004dce5c0ed7fe59a35608f33837c816d80b79f461"),
};

/// X9.62 c2pnb272w1，GF(2^272)，餘因子 65286。
pub const C2PNB272W1: X962F2mNamedCurve<34> = X962F2mNamedCurve {
    m: 272,
    taps: Taps::Pentanomial(1, 3, 56),
    a: hex("91a091f03b5fba4ab2ccf49c4edd220fb028712d42be752b2c40094dbacdb586fb20"),
    b: hex("7167efc92bb2e3ce7c8aaaff34e12a9c557003d7c73a6faf003f99f6cc8482e540f7"),
    order: hex("000100faf51354e0e39e4892df6e319c72c8161603fa45aa7b998a167b8f1e629521"),
    cofactor: 65286,
    gx: hex("6108babb2ceebcf787058a056cbe0cfe622d7723a289e08a07ae13ef0d10d171dd8d"),
    gy: hex("10c7695716851eef6ba7f6872e6142fbd241b830ff5efcaceccab05e02005dde9d23"),
};

/// X9.62 c2pnb304w1，GF(2^304)，餘因子 65070。
pub const C2PNB304W1: X962F2mNamedCurve<38> = X962F2mNamedCurve {
    m: 304,
    taps: Taps::Pentanomial(1, 2, 11),
    a: hex("fd0d693149a118f651e6dce6802085377e5f882d1b510b44160074c1288078365a0396c8e681"),
    b: hex("bddb97e555a50a908e43b01c798ea5daa6788f1ea2794efcf57166b8c14039601e55827340be"),
    order: hex("000101d556572aabac800101d556572aabac8001022d5c91dd173f8fb561da6899164443051d"),
    cofactor: 65070,
    gx: hex("197b07845e9be2d96adb0f5f3c7f2cffbd7a3eb8b6fec35c7fd67f26ddf6285a644f740a2614"),
    gy: hex("e19fbeb76e0da171517ecf401b50289bf014103288527a9b416a105e80260b549fdc1b92c03b"),
};

/// X9.62 c2tnb359v1，GF(2^359)，餘因子 76。
pub const C2TNB359V1: X962F2mNamedCurve<45> = X962F2mNamedCurve {
    m: 359,
    taps: Taps::Trinomial(68),
    a: hex(
        "5667676a654b20754f356ea92017d946567c46675556f19556a04616b567d223a5e05656fb549016a96656a557",
    ),
    b: hex(
        "2472e2d0197c49363f1fe7f5b6db075d52b6947d135d8ca445805d39bc345626089687742b6329e70680231988",
    ),
    order: hex(
        "01af286bca1af286bca1af286bca1af286bca1af286bc9fb8f6b85c556892c20a7eb964fe7719e74f490758d3b",
    ),
    cofactor: 76,
    gx: hex(
        "3c258ef3047767e7ede0f1fdaa79daee3841366a132e163aced4ed2401df9c6bdcde98e8e707c07a2239b1b097",
    ),
    gy: hex(
        "53d7e08529547048121e9c95f3791dd804963948f34fae7bf44ea82365dc7868fe57e4ae2de211305a407104bd",
    ),
};

/// X9.62 c2pnb368w1，GF(2^368)，餘因子 65392。
pub const C2PNB368W1: X962F2mNamedCurve<46> = X962F2mNamedCurve {
    m: 368,
    taps: Taps::Pentanomial(1, 2, 85),
    a: hex(
        "e0d2ee25095206f5e2a4f9ed229f1f256e79a0e2b455970d8d0d865bd94778c576d62f0ab7519ccd2a1a906ae30d",
    ),
    b: hex(
        "fc1217d4320a90452c760a58edcd30c8dd069b3c34453837a34ed50cb54917e1c2112d84d164f444f8f74786046a",
    ),
    order: hex(
        "00010090512da9af72b08349d98a5dd4c7b0532eca51ce03e2d10f3b7ac579bd87e909ae40a6f131e9cfce5bd967",
    ),
    cofactor: 65392,
    gx: hex(
        "1085e2755381dccce3c1557afa10c2f0c0c2825646c5b34a394cbcfa8bc16b22e7e789e927be216f02e1fb136a5f",
    ),
    gy: hex(
        "7b3eb1bddcba62d5d8b2059b525797fc73822c59059c623a45ff3843cee8f87cd1855adaa81e2a0750b80fda2310",
    ),
};

/// X9.62 c2tnb431r1，GF(2^431)，餘因子 10080。
pub const C2TNB431R1: X962F2mNamedCurve<54> = X962F2mNamedCurve {
    m: 431,
    taps: Taps::Trinomial(120),
    a: hex(
        "1a827ef00dd6fc0e234caf046c6a5d8a85395b236cc4ad2cf32a0cadbdc9ddf620b0eb9906d0957f6c6feacd615468df104de296cd8f",
    ),
    b: hex(
        "10d9b4a3d9047d8b154359abfb1b7f5485b04ceb868237ddc9deda982a679a5a919b626d4e50a8dd731b107a9962381fb5d807bf2618",
    ),
    order: hex(
        "000340340340340340340340340340340340340340340340340340340323c313fab50589703b5ec68d3587fec60d161cc149c1ad4a91",
    ),
    cofactor: 10080,
    gx: hex(
        "120fc05d3c67a99de161d2f4092622feca701be4f50f4758714e8a87bbf2a658ef8c21e7c5efe965361f6c2999c0c247b0dbd70ce6b7",
    ),
    gy: hex(
        "20d0af8903a96f8d5fa2c255745d3c451b302c9346d9b7e485e7bce41f6b591f3e8f6addcbb0bc4c2f947a7de1a89b625d6a598b3760",
    ),
};
