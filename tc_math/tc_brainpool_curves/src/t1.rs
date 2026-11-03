use crate::BrainpoolNamedCurve;
use crate::hex::hex;

/// brainpoolP160t1，RFC 5639：與 P160r1 同構，a = −3。
pub const BRAINPOOL_P160T1: BrainpoolNamedCurve<20> = BrainpoolNamedCurve {
    p: hex("e95e4a5f737059dc60dfc7ad95b3d8139515620f"),
    a: hex("e95e4a5f737059dc60dfc7ad95b3d8139515620c"),
    b: hex("7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380"),
    order: hex("e95e4a5f737059dc60df5991d45029409e60fc09"),
    cofactor: 1,
    gx: hex("b199b13b9b34efc1397e64baeb05acc265ff2378"),
    gy: hex("add6718b7c7c1961f0991b842443772152c9e0ad"),
};

/// brainpoolP192t1，RFC 5639：與 P192r1 同構，a = −3。
pub const BRAINPOOL_P192T1: BrainpoolNamedCurve<24> = BrainpoolNamedCurve {
    p: hex("c302f41d932a36cda7a3463093d18db78fce476de1a86297"),
    a: hex("c302f41d932a36cda7a3463093d18db78fce476de1a86294"),
    b: hex("13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79"),
    order: hex("c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1"),
    cofactor: 1,
    gx: hex("3ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129"),
    gy: hex("097e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9"),
};

/// brainpoolP224t1，RFC 5639：與 P224r1 同構，a = −3。
pub const BRAINPOOL_P224T1: BrainpoolNamedCurve<28> = BrainpoolNamedCurve {
    p: hex("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff"),
    a: hex("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0fc"),
    b: hex("4b337d934104cd7bef271bf60ced1ed20da14c08b3bb64f18a60888d"),
    order: hex("d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f"),
    cofactor: 1,
    gx: hex("6ab1e344ce25ff3896424e7ffe14762ecb49f8928ac0c76029b4d580"),
    gy: hex("0374e9f5143e568cd23f3f4d7c0d4b1e41c8cc0d1c6abd5f1a46db4c"),
};

/// brainpoolP256t1，RFC 5639：與 P256r1 同構，a = −3。
pub const BRAINPOOL_P256T1: BrainpoolNamedCurve<32> = BrainpoolNamedCurve {
    p: hex("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377"),
    a: hex("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374"),
    b: hex("662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04"),
    order: hex("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7"),
    cofactor: 1,
    gx: hex("a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4"),
    gy: hex("2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be"),
};

/// brainpoolP320t1，RFC 5639：與 P320r1 同構，a = −3。
pub const BRAINPOOL_P320T1: BrainpoolNamedCurve<40> = BrainpoolNamedCurve {
    p: hex("d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27"),
    a: hex("d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e24"),
    b: hex("a7f561e038eb1ed560b3d147db782013064c19f27ed27c6780aaf77fb8a547ceb5b4fef422340353"),
    order: hex("d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311"),
    cofactor: 1,
    gx: hex("925be9fb01afc6fb4d3e7d4990010f813408ab106c4f09cb7ee07868cc136fff3357f624a21bed52"),
    gy: hex("63ba3a7a27483ebf6671dbef7abb30ebee084e58a0b077ad42a5a0989d1ee71b1b9bc0455fb0d2c3"),
};

/// brainpoolP384t1，RFC 5639：與 P384r1 同構，a = −3。
pub const BRAINPOOL_P384T1: BrainpoolNamedCurve<48> = BrainpoolNamedCurve {
    p: hex(
        "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
    ),
    a: hex(
        "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec50",
    ),
    b: hex(
        "7f519eada7bda81bd826dba647910f8c4b9346ed8ccdc64e4b1abd11756dce1d2074aa263b88805ced70355a33b471ee",
    ),
    order: hex(
        "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
    ),
    cofactor: 1,
    gx: hex(
        "18de98b02db9a306f2afcd7235f72a819b80ab12ebd653172476fecd462aabffc4ff191b946a5f54d8d0aa2f418808cc",
    ),
    gy: hex(
        "25ab056962d30651a114afd2755ad336747f93475b7a1fca3b88f2b6a208ccfe469408584dc2b2912675bf5b9e582928",
    ),
};

/// brainpoolP512t1，RFC 5639：與 P512r1 同構，a = −3。
pub const BRAINPOOL_P512T1: BrainpoolNamedCurve<64> = BrainpoolNamedCurve {
    p: hex(
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
    ),
    a: hex(
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f0",
    ),
    b: hex(
        "7cbbbcf9441cfab76e1890e46884eae321f70c0bcb4981527897504bec3e36a62bcdfa2304976540f6450085f2dae145c22553b465763689180ea2571867423e",
    ),
    order: hex(
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
    ),
    cofactor: 1,
    gx: hex(
        "640ece5c12788717b9c1ba06cbc2a6feba85842458c56dde9db1758d39c0313d82ba51735cdb3ea499aa77a7d6943a64f7a3f25fe26f06b51baa2696fa9035da",
    ),
    gy: hex(
        "5b534bd595f5af0fa2c892376c84ace1bb4e3019b71634c01131159cae03cee9d9932184beef216bd71df2dadf86a627306ecff96dbb8bace198b61e00f8b332",
    ),
};
