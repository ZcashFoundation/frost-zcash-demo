use frost::round1;
use frost_ed25519 as frost;
use participant::{
    generate_key_package, print_values, request_inputs, round_2_request_inputs, Logger,
};
use rand::thread_rng;
use std::io::BufRead;

pub fn cli(input: &mut impl BufRead, logger: &mut dyn Logger) {
    let round_1_config = request_inputs(input, logger).unwrap(); // TODO: handle error
    let _key_package = generate_key_package(&round_1_config).unwrap();
    logger.log("Key Package succesfully created.".to_string());

    let mut rng = thread_rng();
    let (nonces, commitments) = round1::commit(
        round_1_config.identifier,
        &round_1_config.signing_share,
        &mut rng,
    );
    print_values(nonces, commitments, logger);

    let _round_2_config =
        round_2_request_inputs(commitments, round_1_config.identifier, input, logger);
}
