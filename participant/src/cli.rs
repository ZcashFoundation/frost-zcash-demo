#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use crate::round1::{print_values, request_inputs};
use crate::round2::{generate_signature, print_values_round_2, round_2_request_inputs};
use rand::thread_rng;
use std::io::{BufRead, Write};

pub fn cli(
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let round_1_config = request_inputs(input, logger)?;

    let key_package = round_1_config.key_package;

    writeln!(logger, "Key Package succesfully created.")?;

    let mut rng = thread_rng();
    let (nonces, commitments) = frost::round1::commit(key_package.secret_share(), &mut rng);

    print_values(commitments, logger)?;

    let round_2_config = round_2_request_inputs(input, logger)?;

    // Sign

    let signature = generate_signature(round_2_config, &key_package, &nonces)?;

    print_values_round_2(signature, logger)?;

    Ok(())
}
