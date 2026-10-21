//! SEC binary curves with their fields fixed at compile time, after Bouncy Castle's
//! `SecT*` classes; a rewrite of `tc_f2m_custom`.

#![no_std]

extern crate alloc;

mod interleave;
mod sec1;
mod sect113_field;
mod sect113_field_element;
mod sect131_field;
mod sect131_field_element;
mod sect163_field;
mod sect163_field_element;
mod sect193_field;
mod sect193_field_element;
mod sect233_field;
mod sect233_field_element;
mod sect239_field;
mod sect239_field_element;
mod sect283_field;
mod sect283_field_element;
mod sect409_field;
mod sect409_field_element;
mod sect571_field;
mod sect571_field_element;
mod sect_ct_curve;
mod sect_ct_point;
mod sect_element;
mod sect_error;
mod sect_var_curve;
mod sect_var_point;
mod sect_var_precomputed;

pub mod named_curves;

pub use sect_ct_curve::SecTCtCurve;
pub use sect_ct_point::SecTCtPoint;
pub use sect_error::SecTError;
pub use sect_var_curve::SecTVarCurve;
pub use sect_var_point::SecTVarPoint;
pub use sect_var_precomputed::SecTVarPrecomputed;
pub use sect113_field_element::SecT113FieldElement;
pub use sect131_field_element::SecT131FieldElement;
pub use sect163_field_element::SecT163FieldElement;
pub use sect193_field_element::SecT193FieldElement;
pub use sect233_field_element::SecT233FieldElement;
pub use sect239_field_element::SecT239FieldElement;
pub use sect283_field_element::SecT283FieldElement;
pub use sect409_field_element::SecT409FieldElement;
pub use sect571_field_element::SecT571FieldElement;
