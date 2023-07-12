use frost::{round1, Error};
use frost_ed25519 as frost;
use participant::round1::{generate_key_package, print_values, request_inputs};
use participant::round2::{generate_signature, print_values_round_2, round_2_request_inputs};
use participant::Logger;
use rand::thread_rng;
use std::io::BufRead;

#[derive(PartialEq)]
pub enum CliError {
    Config,
    Signing,
    KeyPackage,
}

pub struct ParticipantError {
    pub frost_error: Error,
    pub cli_error: CliError,
}

// This is a little messy because of the use of unwrap(). This can be improved.
pub fn cli(input: &mut impl BufRead, logger: &mut dyn Logger) -> Result<(), ParticipantError> {
    let round_1_config = request_inputs(input, logger);

    if let Err(e) = round_1_config {
        return Err(ParticipantError {
            frost_error: e,
            cli_error: CliError::Config,
        });
    }

    let round_1_config_ok = round_1_config.unwrap();

    let key_package = generate_key_package(&round_1_config_ok);

    if let Err(e) = key_package {
        return Err(ParticipantError {
            frost_error: e,
            cli_error: CliError::KeyPackage,
        });
    }

    let key_package_ok = key_package.unwrap();

    logger.log("Key Package succesfully created.".to_string());

    let mut rng = thread_rng();
    let (nonces, commitments) = round1::commit(&round_1_config_ok.signing_share, &mut rng);

    print_values(&nonces, commitments, logger);

    let round_2_config =
        round_2_request_inputs(round_1_config_ok.identifier, commitments, input, logger); // TODO: handle errors

    if let Err(e) = round_2_config {
        return Err(ParticipantError {
            frost_error: e,
            cli_error: CliError::Config,
        });
    }

    let round_2_config_ok = round_2_config.unwrap();

    // Sign

    let signature = generate_signature(round_2_config_ok, &key_package_ok, &nonces); // TODO: handle errors

    if let Err(e) = signature {
        return Err(ParticipantError {
            frost_error: e,
            cli_error: CliError::Signing,
        });
    }

    print_values_round_2(signature.unwrap(), logger);

    Ok(())
}
