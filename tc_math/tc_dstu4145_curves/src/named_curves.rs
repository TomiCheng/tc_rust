use crate::Dstu4145NamedCurve;
use crate::dstu4145_named_curve::Taps;
use crate::hex::hex;

/// DSTU 4145-2002 的第 0 號曲線，GF(2^163)，OID 1.2.804.2.1.1.1.1.3.1.1.2.0。
pub const DSTU4145_163: Dstu4145NamedCurve<21> = Dstu4145NamedCurve {
    m: 163,
    taps: Taps::Pentanomial(3, 6, 7),
    a: hex("000000000000000000000000000000000000000001"),
    b: hex("05ff6108462a2dc8210ab403925e638a19c1455d21"),
    order: hex("0400000000000000000002bec12be2262d39bcf14d"),
    cofactor: 2,
    gx: hex("02e2f85f5dd74ce983a5c4237229daf8a3f35823be"),
    gy: hex("03826f008a8c51d7b95284d9d03ff0e00ce2cd723a"),
};

/// DSTU 4145-2002 的第 1 號曲線，GF(2^167)，OID 1.2.804.2.1.1.1.1.3.1.1.2.1。
pub const DSTU4145_167: Dstu4145NamedCurve<21> = Dstu4145NamedCurve {
    m: 167,
    taps: Taps::Trinomial(6),
    a: hex("000000000000000000000000000000000000000001"),
    b: hex("6ee3ceeb230811759f20518a0930f1a4315a827dac"),
    order: hex("3fffffffffffffffffffffb12ebcc7d7f29ff7701f"),
    cofactor: 2,
    gx: hex("7a1f6653786a68192803910a3d30b2a2018b21cd54"),
    gy: hex("5f49eb26781c0ec6b8909156d98ed435e45fd59918"),
};

/// DSTU 4145-2002 的第 2 號曲線，GF(2^173)，OID 1.2.804.2.1.1.1.1.3.1.1.2.2。
pub const DSTU4145_173: Dstu4145NamedCurve<22> = Dstu4145NamedCurve {
    m: 173,
    taps: Taps::Pentanomial(1, 2, 10),
    a: hex("00000000000000000000000000000000000000000000"),
    b: hex("108576c80499db2fc16eddf6853bbb278f6b6fb437d9"),
    order: hex("0800000000000000000000189b4e67606e3825bb2831"),
    cofactor: 4,
    gx: hex("04d41a619bcc6eadf0448fa22fad567a9181d37389ca"),
    gy: hex("10b51cc12849b234c75e6dd2028bf7ff5c1ce0d991a1"),
};

/// DSTU 4145-2002 的第 3 號曲線，GF(2^179)，OID 1.2.804.2.1.1.1.1.3.1.1.2.3。
pub const DSTU4145_179: Dstu4145NamedCurve<23> = Dstu4145NamedCurve {
    m: 179,
    taps: Taps::Pentanomial(1, 2, 4),
    a: hex("0000000000000000000000000000000000000000000001"),
    b: hex("04a6e0856526436f2f88dd07a341e32d04184572beb710"),
    order: hex("03ffffffffffffffffffffffb981960435fe5ab64236ef"),
    cofactor: 2,
    gx: hex("06ba06fe51464b2bd26dc57f48819ba9954667022c7d03"),
    gy: hex("025fbc363582dcec065080ca8287aaff09788a66dc3a9e"),
};

/// DSTU 4145-2002 的第 4 號曲線，GF(2^191)，OID 1.2.804.2.1.1.1.1.3.1.1.2.4。
pub const DSTU4145_191: Dstu4145NamedCurve<24> = Dstu4145NamedCurve {
    m: 191,
    taps: Taps::Trinomial(9),
    a: hex("000000000000000000000000000000000000000000000001"),
    b: hex("7bc86e2102902ec4d5890e8b6b4981ff27e0482750fefc03"),
    order: hex("40000000000000000000000069a779cac1dabc6788f7474f"),
    cofactor: 2,
    gx: hex("714114b762f2ff4a7912a6d2ac58b9b5c2fcfe76daeb7129"),
    gy: hex("29c41e568b77c617efe5902f11db96fa9613cd8d03db08da"),
};

/// DSTU 4145-2002 的第 5 號曲線，GF(2^233)，OID 1.2.804.2.1.1.1.1.3.1.1.2.5。
pub const DSTU4145_233: Dstu4145NamedCurve<30> = Dstu4145NamedCurve {
    m: 233,
    taps: Taps::Pentanomial(1, 4, 9),
    a: hex("000000000000000000000000000000000000000000000000000000000001"),
    b: hex("006973b15095675534c7cf7e64a21bd54ef5dd3b8a0326aa936ece454d2c"),
    order: hex("01000000000000000000000000000013e974e72f8a6922031d2603cfe0d7"),
    cofactor: 2,
    gx: hex("003fcda526b6cdf83ba1118df35b3c31761d3545f32728d003eeb25efe96"),
    gy: hex("009ca8b57a934c54deeda9e54a7bbad95e3b2e91c54d32be0b9df96d8d35"),
};

/// DSTU 4145-2002 的第 6 號曲線，GF(2^257)，OID 1.2.804.2.1.1.1.1.3.1.1.2.6。
pub const DSTU4145_257: Dstu4145NamedCurve<33> = Dstu4145NamedCurve {
    m: 257,
    taps: Taps::Trinomial(12),
    a: hex("000000000000000000000000000000000000000000000000000000000000000000"),
    b: hex("01cef494720115657e18f938d7a7942394ff9425c1458c57861f9eea6adbe3be10"),
    order: hex("00800000000000000000000000000000006759213af182e987d3e17714907d470d"),
    cofactor: 4,
    gx: hex("002a29ef207d0e9b6c55cd260b306c7e007ac491ca1b10c62334a9e8dcd8d20fb7"),
    gy: hex("010686d41ff744d4449fccf6d8eea03102e6812c93a9d60b978b702cf156d814ef"),
};

/// DSTU 4145-2002 的第 7 號曲線，GF(2^307)，OID 1.2.804.2.1.1.1.1.3.1.1.2.7。
pub const DSTU4145_307: Dstu4145NamedCurve<39> = Dstu4145NamedCurve {
    m: 307,
    taps: Taps::Pentanomial(2, 4, 8),
    a: hex("000000000000000000000000000000000000000000000000000000000000000000000000000001"),
    b: hex("0393c7f7d53666b5054b5e6c6d3de94f4296c0c599e2e2e241050df18b6090bdc90186904968bb"),
    order: hex("03ffffffffffffffffffffffffffffffffffffffc079c2f3825da70d390fbba588d4604022b7b7"),
    cofactor: 2,
    gx: hex("0216ee8b189d291a0224984c1e92f1d16bf75ccd825a087a239b276d3167743c52c02d6e7232aa"),
    gy: hex("05d9306bacd22b7faeb09d2e049c6e2866c5d1677762a8f2f2dc9a11c7f7be8340ab2237c7f2a0"),
};

/// DSTU 4145-2002 的第 8 號曲線，GF(2^367)，OID 1.2.804.2.1.1.1.1.3.1.1.2.8。
pub const DSTU4145_367: Dstu4145NamedCurve<46> = Dstu4145NamedCurve {
    m: 367,
    taps: Taps::Trinomial(21),
    a: hex(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
    ),
    b: hex(
        "43fc8ad242b0b7a6f3d1627ad5654447556b47bf6aa4a64b0c2afe42cadab8f93d92394c79a79755437b56995136",
    ),
    order: hex(
        "40000000000000000000000000000000000000000000009c300b75a3fa824f22428fd28ce8812245ef44049b2d49",
    ),
    cofactor: 2,
    gx: hex(
        "324a6eddd512f08c49a99ae0d3f961197a76413e7be81a400ca681e09639b5fe12e59a109f78bf4a373541b3b9a1",
    ),
    gy: hex(
        "01ab597a5b4477f59e39539007c7f977d1a567b92b043a49c6b61984c3fe3481aaf454cd41ba1f051626442b3c10",
    ),
};

/// DSTU 4145-2002 的第 9 號曲線，GF(2^431)，OID 1.2.804.2.1.1.1.1.3.1.1.2.9。
pub const DSTU4145_431: Dstu4145NamedCurve<54> = Dstu4145NamedCurve {
    m: 431,
    taps: Taps::Pentanomial(1, 3, 5),
    a: hex(
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
    ),
    b: hex(
        "03ce10490f6a708fc26dfe8c3d27c4f94e690134d5bff988d8d28aaeaede975936c66bac536b18ae2dc312ca493117daa469c640caf3",
    ),
    order: hex(
        "3fffffffffffffffffffffffffffffffffffffffffffffffffffffba3175458009a8c0a724f02f81aa8a1fcbaf80d90c7a95110504cf",
    ),
    cofactor: 2,
    gx: hex(
        "1a62ba79d98133a16bbae7ed9a8e03c32e0824d57aef72f88986874e5aae49c27bed49a2a95058068426c2171e99fd3b43c5947c857d",
    ),
    gy: hex(
        "70b5e1e14031c1f70bbefe96bdde66f451754b4ca5f48da241f331aa396b8d1839a855c1769b1ea14ba53308b5e2723724e090e02db9",
    ),
};
