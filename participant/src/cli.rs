use frost::round1;
use frost_ed25519 as frost;
use participant::round1::{generate_key_package, print_values, request_inputs};
use participant::round2::{generate_signature, print_values_round_2, round_2_request_inputs};
use participant::Logger;
use rand::thread_rng;
use std::io::BufRead;

pub fn cli(input: &mut impl BufRead, logger: &mut dyn Logger) {
    let round_1_config = request_inputs(input, logger).unwrap(); // TODO: handle error
    let key_package = generate_key_package(&round_1_config).unwrap();
    logger.log("Key Package succesfully created.".to_string());

    let mut rng = thread_rng();
    let (nonces, commitments) = round1::commit(
        round_1_config.identifier,
        &round_1_config.signing_share,
        &mut rng,
    );
    print_values(&nonces, commitments, logger);

    let round_2_config = round_2_request_inputs(commitments, input, logger).unwrap(); // TODO: handle errors

    // Sign

    let signature = generate_signature(round_2_config, &key_package, &nonces).unwrap(); // TODO: handle errors

    print_values_round_2(signature, logger);
}
