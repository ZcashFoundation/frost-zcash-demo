#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::{round1::SigningCommitments, Identifier, SigningPackage};

use std::{
    collections::BTreeMap,
    io::{BufRead, Write},
};

#[derive(Debug, PartialEq, Clone)]
pub struct CommitmentsConfig {
    pub message: Vec<u8>,
    pub signer_commitments: BTreeMap<Identifier, SigningCommitments>,
}

pub fn step_2(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    commitments: BTreeMap<Identifier, SigningCommitments>,
) -> Result<SigningPackage, Box<dyn std::error::Error>> {
    let signing_package = request_message(input, logger, commitments)?;
    print_signing_package(logger, &signing_package);
    Ok(signing_package)
}

// Input required:
// 1. message
fn request_message(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    commitments: BTreeMap<Identifier, SigningCommitments>,
) -> Result<SigningPackage, Box<dyn std::error::Error>> {
    writeln!(logger, "The message to be signed (hex encoded)")?;

    let mut msg = String::new();
    input.read_line(&mut msg)?;

    let message = hex::decode(msg.trim())?;

    let signing_package = SigningPackage::new(commitments, &message);

    Ok(signing_package)
}

fn print_signing_package(logger: &mut dyn Write, signing_package: &SigningPackage) {
    writeln!(
        logger,
        "Signing Package:\n{}",
        serde_json::to_string(&signing_package).unwrap()
    )
    .unwrap();
}
