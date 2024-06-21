use frost_core::{self as frost, Ciphersuite};

use frost::{round1::SigningCommitments, Identifier, SigningPackage};

use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, Write},
};

use crate::args::Args;

#[derive(Debug, PartialEq, Clone)]
pub struct CommitmentsConfig<C: Ciphersuite> {
    pub message: Vec<u8>,
    pub signer_commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
}

pub fn step_2<C: Ciphersuite>(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
) -> Result<SigningPackage<C>, Box<dyn std::error::Error>> {
    let signing_package = request_message(args, input, logger, commitments)?;
    print_signing_package(logger, &signing_package);
    Ok(signing_package)
}

// Input required:
// 1. message
fn request_message<C: Ciphersuite>(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
) -> Result<SigningPackage<C>, Box<dyn std::error::Error>> {
    let message = if args.message.is_empty() {
        writeln!(logger, "The message to be signed (hex encoded)")?;

        let mut msg = String::new();
        input.read_line(&mut msg)?;

        hex::decode(msg.trim())?
    } else {
        eprintln!("Reading message from {}...", &args.message);
        fs::read(&args.message)?
    };

    let signing_package = SigningPackage::new(commitments, &message);

    Ok(signing_package)
}

fn print_signing_package<C: Ciphersuite>(
    logger: &mut dyn Write,
    signing_package: &SigningPackage<C>,
) {
    writeln!(
        logger,
        "Signing Package:\n{}",
        serde_json::to_string(&signing_package).unwrap()
    )
    .unwrap();
}
