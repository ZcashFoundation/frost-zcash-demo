use participant::{generate_key_package, request_inputs, Logger};
use std::io::BufRead;

pub fn cli(input: &mut impl BufRead, logger: &mut dyn Logger) {
    let config = request_inputs(input, logger).unwrap(); // TODO: handle error
    let _key_package = generate_key_package(config);
    logger.log("Key Package succesfully created.".to_string());
}
