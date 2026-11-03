use crate::GostNamedCurve;
use crate::cryptopro::{
    GOSTR3410_2001_CRYPTOPRO_A, GOSTR3410_2001_CRYPTOPRO_B, GOSTR3410_2001_CRYPTOPRO_C,
};
use crate::hex::hex;

/// Tc26-Gost-3410-12-256-paramSetA，RFC 7836；餘因子為 4。
pub const TC26_GOST_3410_12_256_PARAMSET_A: GostNamedCurve<32> = GostNamedCurve {
    p: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97"),
    a: hex("c2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335"),
    b: hex("295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513"),
    order: hex("400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67"),
    cofactor: 4,
    gx: hex("91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28"),
    gy: hex("32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c"),
};

/// Tc26-Gost-3410-12-256-paramSetB：與 CryptoPro-A 同一組參數。
pub const TC26_GOST_3410_12_256_PARAMSET_B: GostNamedCurve<32> = GOSTR3410_2001_CRYPTOPRO_A;

/// Tc26-Gost-3410-12-256-paramSetC：與 CryptoPro-B 同一組參數。
pub const TC26_GOST_3410_12_256_PARAMSET_C: GostNamedCurve<32> = GOSTR3410_2001_CRYPTOPRO_B;

/// Tc26-Gost-3410-12-256-paramSetD：與 CryptoPro-C 同一組參數。
pub const TC26_GOST_3410_12_256_PARAMSET_D: GostNamedCurve<32> = GOSTR3410_2001_CRYPTOPRO_C;

/// Tc26-Gost-3410-12-512-paramSetA，RFC 7836。
pub const TC26_GOST_3410_12_512_PARAMSET_A: GostNamedCurve<64> = GostNamedCurve {
    p: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7"),
    a: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc4"),
    b: hex("e8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b6265ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c760"),
    order: hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275"),
    cofactor: 1,
    gx: hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003"),
    gy: hex("7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa921df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2a4"),
};

/// Tc26-Gost-3410-12-512-paramSetB，RFC 7836。
pub const TC26_GOST_3410_12_512_PARAMSET_B: GostNamedCurve<64> = GostNamedCurve {
    p: hex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f"),
    a: hex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c"),
    b: hex("687d1b459dc841457e3e06cf6f5e2517b97c7d614af138bcbf85dc806c4b289f3e965d2db1416d217f8b276fad1ab69c50f78bee1fa3106efb8ccbc7c5140116"),
    order: hex("800000000000000000000000000000000000000000000000000000000000000149a1ec142565a545acfdb77bd9d40cfa8b996712101bea0ec6346c54374f25bd"),
    cofactor: 1,
    gx: hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"),
    gy: hex("1a8f7eda389b094c2c071e3647a8940f3c123b697578c213be6dd9e6c8ec7335dcb228fd1edf4a39152cbcaaf8c0398828041055f94ceeec7e21340780fe41bd"),
};

/// Tc26-Gost-3410-12-512-paramSetC，RFC 7836；餘因子為 4。
pub const TC26_GOST_3410_12_512_PARAMSET_C: GostNamedCurve<64> = GostNamedCurve {
    p: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7"),
    a: hex("dc9203e514a721875485a529d2c722fb187bc8980eb866644de41c68e143064546e861c0e2c9edd92ade71f46fcf50ff2ad97f951fda9f2a2eb6546f39689bd3"),
    b: hex("b4c4ee28cebc6c2c8ac12952cf37f16ac7efb6a9f69f4b57ffda2e4f0de5ade038cbc2fff719d2c18de0284b8bfef3b52b8cc7a5f5bf0a3c8d2319a5312557e1"),
    order: hex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed"),
    cofactor: 4,
    gx: hex("e2e31edfc23de7bdebe241ce593ef5de2295b7a9cbaef021d385f7074cea043aa27272a7ae602bf2a7b9033db9ed3610c6fb85487eae97aac5bc7928c1950148"),
    gy: hex("f5ce40d95b5eb899abbccff5911cb8577939804d6527378b8c108c3d2090ff9be18e2d33e3021ed2ef32d85822423b6304f726aa854bae07d0396e9a9addc40f"),
};
