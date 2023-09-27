use frost::{Error, Signature};
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

    let config_message = round_2_config.clone();

    // Sign

    let signature = generate_signature(round_2_config, &key_package, &nonces)?;

    print_values_round_2(signature, logger)?;

    let group_signature = request_signature(input, logger)?;
    key_package
        .group_public()
        .verify(config_message.signing_package.message(), &group_signature)?;

    writeln!(logger, "Group Signature verified.")?;

    Ok(())
}

fn request_signature(
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<Signature, Box<dyn std::error::Error>> {
    writeln!(logger, "The group signature:")?;

    let mut signature_input = String::new();

    input.read_line(&mut signature_input)?;

    let group_signature =
        serde_json::from_str(signature_input.trim()).map_err(|_| Error::InvalidSignature)?;

    // TODO: add redpallas feature

    Ok(group_signature)
}
