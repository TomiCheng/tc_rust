use std::io;

// BC's IStreamCalculator: the input is written in, as much at a time as wanted, and the result
// is taken once everything is written. Taking it ends the calculator
pub trait StreamCalculator<T>: io::Write {
    fn result(self: Box<Self>) -> T;
}
