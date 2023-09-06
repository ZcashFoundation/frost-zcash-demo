#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas::keys::PositiveY;

use frost::keys::dkg::{round1, round2};
use frost::Identifier;
use rand::thread_rng;
use std::collections::HashMap;
use std::io::{BufRead, Write};

use crate::inputs::{read_round1_package, read_round2_package, request_inputs};

pub fn cli(
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = request_inputs(reader, logger)?;

    let rng = thread_rng();

    let (secret_package, package) = frost::keys::dkg::part1(
        config.identifier,
        config.max_signers,
        config.min_signers,
        rng,
    )?;

    writeln!(logger, "\n=== ROUND 1: SEND PACKAGES ===\n")?;

    writeln!(
        logger,
        "Round 1 Package to send to all other participants (your identifier: {}):\n\n{}\n",
        serde_json::to_string(&config.identifier)?,
        serde_json::to_string(&package)?
    )?;

    writeln!(logger, "=== ROUND 1: RECEIVE PACKAGES ===\n")?;

    writeln!(
        logger,
        "Input Round 1 Packages from the other {} participants.\n",
        config.max_signers - 1,
    )?;
    let mut received_round1_packages: HashMap<Identifier, round1::Package> = HashMap::new();
    for _ in 0..config.max_signers - 1 {
        let (identifier, round1_package) = read_round1_package(reader, logger)?;
        received_round1_packages.insert(identifier, round1_package);
        writeln!(logger)?;
    }

    let (round2_secret_package, round2_packages) =
        frost::keys::dkg::part2(secret_package, &received_round1_packages)?;

    writeln!(logger, "=== ROUND 2: SEND PACKAGES ===\n")?;

    for (identifier, package) in round2_packages {
        writeln!(
            logger,
            "Round 2 Package to send to participant {} (your identifier: {}):\n\n{}\n",
            serde_json::to_string(&identifier)?,
            serde_json::to_string(&config.identifier)?,
            serde_json::to_string(&package)?
        )?;
    }

    writeln!(logger, "=== ROUND 2: RECEIVE PACKAGES ===\n")?;

    writeln!(
        logger,
        "Input Round 2 Packages from the other {} participants.\n",
        config.max_signers - 1,
    )?;
    let mut received_round2_packages: HashMap<Identifier, round2::Package> = HashMap::new();
    for _ in 0..config.max_signers - 1 {
        let (identifier, round2_package) = read_round2_package(reader, logger)?;
        received_round2_packages.insert(identifier, round2_package);
        writeln!(logger)?;
    }

    writeln!(logger, "=== DKG FINISHED ===")?;

    let (key_package, public_key_package) = frost::keys::dkg::part3(
        &round2_secret_package,
        &received_round1_packages,
        &received_round2_packages,
    )?;
    #[cfg(feature = "redpallas")]
    let public_key_package = public_key_package.into_positive_y();
    #[cfg(feature = "redpallas")]
    let key_package = key_package.into_positive_y();

    writeln!(
        logger,
        "Participant key package:\n\n{}\n",
        serde_json::to_string(&key_package)?,
    )?;
    writeln!(
        logger,
        "Participant public key package:\n\n{}\n",
        serde_json::to_string(&public_key_package)?,
    )?;

    Ok(())
}
