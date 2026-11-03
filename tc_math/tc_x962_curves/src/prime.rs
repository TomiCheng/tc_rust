use crate::X962FpNamedCurve;
use crate::hex::hex;

/// X9.62 prime192v2。
pub const PRIME192V2: X962FpNamedCurve<24> = X962FpNamedCurve {
    p: hex("fffffffffffffffffffffffffffffffeffffffffffffffff"),
    a: hex("fffffffffffffffffffffffffffffffefffffffffffffffc"),
    b: hex("cc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953"),
    order: hex("fffffffffffffffffffffffe5fb1a724dc80418648d8dd31"),
    cofactor: 1,
    gx: hex("eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a"),
    gy: hex("6574d11d69b6ec7a672bb82a083df2f2b0847de970b2de15"),
};

/// X9.62 prime192v3。
pub const PRIME192V3: X962FpNamedCurve<24> = X962FpNamedCurve {
    p: hex("fffffffffffffffffffffffffffffffeffffffffffffffff"),
    a: hex("fffffffffffffffffffffffffffffffefffffffffffffffc"),
    b: hex("22123dc2395a05caa7423daeccc94760a7d462256bd56916"),
    order: hex("ffffffffffffffffffffffff7a62d031c83f4294f640ec13"),
    cofactor: 1,
    gx: hex("7d29778100c65a1da1783716588dce2b8b4aee8e228f1896"),
    gy: hex("38a90f22637337334b49dcb66a6dc8f9978aca7648a943b0"),
};

/// X9.62 prime239v1。
pub const PRIME239V1: X962FpNamedCurve<30> = X962FpNamedCurve {
    p: hex("7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff"),
    a: hex("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc"),
    b: hex("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a"),
    order: hex("7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b"),
    cofactor: 1,
    gx: hex("0ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf"),
    gy: hex("7debe8e4e90a5dae6e4054ca530ba04654b36818ce226b39fccb7b02f1ae"),
};

/// X9.62 prime239v2。
pub const PRIME239V2: X962FpNamedCurve<30> = X962FpNamedCurve {
    p: hex("7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff"),
    a: hex("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc"),
    b: hex("617fab6832576cbbfed50d99f0249c3fee58b94ba0038c7ae84c8c832f2c"),
    order: hex("7fffffffffffffffffffffff800000cfa7e8594377d414c03821bc582063"),
    cofactor: 1,
    gx: hex("38af09d98727705120c921bb5e9e26296a3cdcf2f35757a0eafd87b830e7"),
    gy: hex("5b0125e4dbea0ec7206da0fc01d9b081329fb555de6ef460237dff8be4ba"),
};

/// X9.62 prime239v3。
pub const PRIME239V3: X962FpNamedCurve<30> = X962FpNamedCurve {
    p: hex("7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff"),
    a: hex("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc"),
    b: hex("255705fa2a306654b1f4cb03d6a750a30c250102d4988717d9ba15ab6d3e"),
    order: hex("7fffffffffffffffffffffff7fffff975deb41b3a6057c3c432146526551"),
    cofactor: 1,
    gx: hex("6768ae8e18bb92cfcf005c949aa2c6d94853d0e660bbf854b1c9505fe95a"),
    gy: hex("1607e6898f390c06bc1d552bad226f3b6fcfe48b6e818499af18e3ed6cf3"),
};
