pub mod round1;
pub mod round2;

pub trait Logger {
    fn log(&mut self, value: String);
}
