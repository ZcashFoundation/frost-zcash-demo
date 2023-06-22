use frost::keys::dkg::{round1, round2};
use frost::{Error, Identifier};
use frost_ed25519 as frost;
use rand::thread_rng;
use std::collections::HashMap;
use std::io;

use crate::inputs::{read_round1_package, read_round2_package, request_inputs};
use crate::output::Logger;

#[derive(PartialEq)]
pub enum CliError {
    Config,
    Keygen,
}

pub struct TrustedDealerError {
    pub frost_error: Error,
    pub cli_error: CliError,
}

pub fn cli() -> Result<(), TrustedDealerError> {
    let mut reader = Box::new(io::stdin().lock());
    let config = request_inputs(&mut reader);
    if let Err(e) = config {
        return Err(TrustedDealerError {
            frost_error: e,
            cli_error: CliError::Config,
        });
    }

    let config = config.unwrap();

    let rng = thread_rng();

    let (secret_package, package) = frost::keys::dkg::part1(
        config.identifier,
        config.max_signers,
        config.min_signers,
        rng,
    )
    .map_err(|e| TrustedDealerError {
        frost_error: e,
        cli_error: CliError::Keygen,
    })?;

    let mut console_logger = ConsoleLogger::default();

    console_logger.log("\n=== ROUND 1: SEND PACKAGES ===\n".to_string());

    console_logger.log(format!(
        "Round 1 Package to send to all other participants (your identifier: {}):\n\n{}\n",
        serde_json::to_string(&config.identifier).unwrap(),
        serde_json::to_string(&package).unwrap()
    ));

    console_logger.log("=== ROUND 1: RECEIVE PACKAGES ===\n".to_string());

    console_logger.log(format!(
        "Input Round 1 Packages from the other {} participants.\n",
        config.max_signers - 1,
    ));
    let mut received_round1_packages: HashMap<Identifier, round1::Package> = HashMap::new();
    for _ in 0..config.max_signers - 1 {
        let (identifier, round1_package) =
            read_round1_package(&mut reader).map_err(|e| TrustedDealerError {
                frost_error: e,
                cli_error: CliError::Keygen,
            })?;
        received_round1_packages.insert(identifier, round1_package);
        console_logger.log("".to_string());
    }
    let received_round1_packages = received_round1_packages.into_values().collect::<Vec<_>>();

    let (round2_secret_package, round2_packages) =
        frost::keys::dkg::part2(secret_package, &received_round1_packages).map_err(|e| {
            TrustedDealerError {
                frost_error: e,
                cli_error: CliError::Keygen,
            }
        })?;

    console_logger.log("=== ROUND 2: SEND PACKAGES ===\n".to_string());

    for package in round2_packages {
        console_logger.log(format!(
            "Round 2 Package to send to participant {} (your identifier: {}):\n\n{}\n",
            serde_json::to_string(package.receiver_identifier()).unwrap(),
            serde_json::to_string(&config.identifier).unwrap(),
            serde_json::to_string(&package).unwrap()
        ));
    }

    console_logger.log("=== ROUND 2: RECEIVE PACKAGES ===\n".to_string());

    console_logger.log(format!(
        "Input Round 2 Packages from the other {} participants.\n",
        config.max_signers - 1,
    ));
    let mut received_round2_packages: HashMap<Identifier, round2::Package> = HashMap::new();
    for _ in 0..config.max_signers - 1 {
        let (identifier, round2_package) =
            read_round2_package(&mut reader).map_err(|e| TrustedDealerError {
                frost_error: e,
                cli_error: CliError::Keygen,
            })?;
        received_round2_packages.insert(identifier, round2_package);
        console_logger.log("".to_string());
    }
    let received_round2_packages = received_round2_packages.into_values().collect::<Vec<_>>();

    console_logger.log("=== DKG FINISHED ===".to_string());

    let (key_package, public_key_package) = frost::keys::dkg::part3(
        &round2_secret_package,
        &received_round1_packages,
        &received_round2_packages,
    )
    .map_err(|e| TrustedDealerError {
        frost_error: e,
        cli_error: CliError::Keygen,
    })?;

    console_logger.log(format!(
        "Participant key package:\n\n{}\n",
        serde_json::to_string(&key_package).unwrap(),
    ));
    console_logger.log(format!(
        "Partcipant public key package:\n\n{}\n",
        serde_json::to_string(&public_key_package).unwrap(),
    ));

    Ok(())
}

#[derive(Default)]
pub struct ConsoleLogger;

impl Logger for ConsoleLogger {
    fn log(&mut self, value: String) {
        println!("{}", value);
    }
}
