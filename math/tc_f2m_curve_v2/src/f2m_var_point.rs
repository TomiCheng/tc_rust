use crate::{F2mFieldElement, F2mVarCurve};

// BC's F2m coordinate systems. The lambda forms keep `l = x + y / x` in place of `y`.
#[derive(Clone)]
enum Coords {
    Affine {
        x: F2mFieldElement,
        y: F2mFieldElement,
    },
    Homogeneous {
        x: F2mFieldElement,
        y: F2mFieldElement,
        z: F2mFieldElement,
    },
    LambdaAffine {
        x: F2mFieldElement,
        l: F2mFieldElement,
    },
    LambdaProjective {
        x: F2mFieldElement,
        l: F2mFieldElement,
        z: F2mFieldElement,
    },
}

#[derive(Clone)]
pub struct F2mVarPoint<'a> {
    curve: &'a F2mVarCurve,
    coords: Option<Coords>,
}
