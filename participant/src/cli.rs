use frost::round1;
use frost_ed25519 as frost;
use participant::{generate_key_package, print_values, request_inputs, Logger};
use rand::thread_rng;
use std::io::BufRead;

pub fn cli(input: &mut impl BufRead, logger: &mut dyn Logger) {
    let config = request_inputs(input, logger).unwrap(); // TODO: handle error
    let _key_package = generate_key_package(&config);
    logger.log("Key Package succesfully created.".to_string());

    let mut rng = thread_rng();
    let (nonces, commitments) = round1::commit(config.identifier, &config.signing_share, &mut rng);
    print_values(nonces, commitments, logger);
}
