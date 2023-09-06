#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::round1;
use participant::round1::{print_values, request_inputs};
use participant::round2::{generate_signature, print_values_round_2, round_2_request_inputs};
use rand::thread_rng;
use std::io::{BufRead, Write};

// Update to use specific errors as below

pub fn cli(
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let round_1_config = request_inputs(input, logger)?;

    let key_package = round_1_config.key_package;

    writeln!(logger, "Key Package succesfully created.")?;

    let mut rng = thread_rng();
    let (nonces, commitments) = round1::commit(key_package.secret_share(), &mut rng);

    print_values(commitments, logger)?;

    let round_2_config = round_2_request_inputs(input, logger)?;

    // Sign

    let signature = generate_signature(round_2_config, &key_package, &nonces)?; // TODO: handle errors

    print_values_round_2(signature, logger)?;

    Ok(())
}

// #[derive(PartialEq)]
// pub enum CliError {
//     Config,
//     Signing,
// }

// pub struct ParticipantError {
//     pub frost_error: Error,
//     pub cli_error: CliError,
// }

// This is a little messy because of the use of unwrap(). This can be improved.
// pub fn cli(   input: &mut impl BufRead,
//     logger: &mut impl Write,) -> Result<(), ParticipantError> {
//     let round_1_config = request_inputs(input, logger);

//     if let Err(e) = round_1_config {
//         return Err(ParticipantError {
//             frost_error: e,
//             cli_error: CliError::Config,
//         });
//     }

//     let round_1_config_ok = round_1_config.unwrap();

//     let key_package_ok = round_1_config_ok.key_package;

//     writeln!(logger, "Key Package succesfully created.");

//     let mut rng = thread_rng();
//     let (nonces, commitments) = round1::commit(key_package_ok.secret_share(), &mut rng);

//     print_values(commitments, logger);

//     let round_2_config = round_2_request_inputs(input, logger); // TODO: handle errors

//     if let Err(e) = round_2_config {
//         return Err(ParticipantError {
//             frost_error: e,
//             cli_error: CliError::Config,
//         });
//     }

//     let round_2_config_ok = round_2_config.unwrap();

//     // Sign

//     let signature = generate_signature(round_2_config_ok, &key_package_ok, &nonces); // TODO: handle errors

//     if let Err(e) = signature {
//         return Err(ParticipantError {
//             frost_error: e,
//             cli_error: CliError::Signing,
//         });
//     }

//     print_values_round_2(signature.unwrap(), logger);

//     Ok(())
// }
