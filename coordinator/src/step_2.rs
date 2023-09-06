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
    participants: Vec<Identifier>,
) -> Result<SigningPackage, Box<dyn std::error::Error>> {
    let signing_package = request_inputs_commitments(input, logger, participants)?;
    print_commitments(logger, &signing_package);
    Ok(signing_package)
}

// Input required:
// 1. message
// 2. number of signers
// 3. commitments for all signers
fn request_inputs_commitments(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    participants: Vec<Identifier>,
) -> Result<SigningPackage, Box<dyn std::error::Error>> {
    writeln!(logger, "The message to be signed (hex encoded)")?;

    let mut msg = String::new();
    input.read_line(&mut msg)?;

    let message = hex::decode(msg.trim())?;

    let mut commitments_list: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

    for p in participants {
        writeln!(
            logger,
            "Please enter JSON encoded commitments for participant {}:",
            hex::encode(p.serialize())
        )?; // TODO: improve printing

        let mut commitments_input = String::new();
        input.read_line(&mut commitments_input)?;
        let commitments = serde_json::from_str(&commitments_input)?;
        commitments_list.insert(p, commitments);
    }

    let signing_package = SigningPackage::new(commitments_list, &message);

    Ok(signing_package)
}

fn print_commitments(logger: &mut dyn Write, signing_package: &SigningPackage) {
    writeln!(
        logger,
        "Signing Package:\n{}",
        serde_json::to_string(&signing_package).unwrap()
    )
    .unwrap();
}
