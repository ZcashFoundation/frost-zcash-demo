use participant::{request_inputs, Logger};
use std::io::BufRead;

pub fn cli(input: &mut impl BufRead, logger: &mut dyn Logger) {
    let _config = request_inputs(input, logger);
}
