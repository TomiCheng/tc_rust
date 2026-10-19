//! SEC binary curves with their fields fixed at compile time, after Bouncy Castle's
//! `SecT*` classes; a rewrite of `tc_f2m_custom`.

#![no_std]

mod sect163_field_element;
mod sect233_field_element;
mod sect_ct_curve;
mod sect_ct_point;
mod sect_element;
mod sect_var_curve;
mod sect_var_point;

pub mod named_curves;

pub use sect_ct_curve::SecTCtCurve;
pub use sect_ct_point::SecTCtPoint;
pub use sect_var_curve::SecTVarCurve;
pub use sect_var_point::SecTVarPoint;
pub use sect163_field_element::SecT163FieldElement;
pub use sect233_field_element::SecT233FieldElement;
