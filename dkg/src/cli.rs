use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::{self as frost, Ciphersuite};

use rand::thread_rng;
use reddsa::frost::redpallas::keys::EvenY;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use crate::inputs::{read_round1_package, read_round2_package, request_inputs};

// The redpallas ciphersuite requires ensuring public key have an even Y
// coordinate. Since the code uses generics, this trait is used to convert if
// needed depending on the ciphersuite.
//
// If you are adding a new ciphersuite to this tool which does note require
// this, just implement it and the default implementation (which does nothing)
// will suffice. See below.
pub trait MaybeIntoEvenY: Ciphersuite {
    fn into_even_y(
        key_packages: (KeyPackage<Self>, PublicKeyPackage<Self>),
    ) -> (KeyPackage<Self>, PublicKeyPackage<Self>) {
        key_packages
    }
}

// A ciphersuite that does not need the conversion.
impl MaybeIntoEvenY for frost_ed25519::Ed25519Sha512 {}

impl MaybeIntoEvenY for reddsa::frost::redpallas::PallasBlake2b512 {
    fn into_even_y(
        (key_package, public_key_package): (KeyPackage<Self>, PublicKeyPackage<Self>),
    ) -> (KeyPackage<Self>, PublicKeyPackage<Self>) {
        let is_even = public_key_package.has_even_y();
        (
            key_package.into_even_y(Some(is_even)),
            public_key_package.into_even_y(Some(is_even)),
        )
    }
}

pub fn cli<C: Ciphersuite + 'static + MaybeIntoEvenY>(
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = request_inputs::<C>(reader, logger)?;

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
    let mut received_round1_packages = BTreeMap::new();
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
    let mut received_round2_packages = BTreeMap::new();
    for _ in 0..config.max_signers - 1 {
        let (identifier, round2_package) = read_round2_package(reader, logger)?;
        received_round2_packages.insert(identifier, round2_package);
        writeln!(logger)?;
    }

    writeln!(logger, "=== DKG FINISHED ===")?;

    let (key_package, public_key_package) = MaybeIntoEvenY::into_even_y(frost::keys::dkg::part3(
        &round2_secret_package,
        &received_round1_packages,
        &received_round2_packages,
    )?);

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
