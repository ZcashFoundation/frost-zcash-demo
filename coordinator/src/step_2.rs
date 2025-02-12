use frost_core::{self as frost, Ciphersuite};

use frost::{round1::SigningCommitments, Identifier, SigningPackage};

use std::{collections::BTreeMap, io::Write};

use crate::args::ProcessedArgs;

#[derive(Debug, PartialEq, Clone)]
pub struct CommitmentsConfig<C: Ciphersuite> {
    pub message: Vec<u8>,
    pub signer_commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
}

pub fn step_2<C: Ciphersuite>(
    args: &ProcessedArgs<C>,
    logger: &mut dyn Write,
    commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
) -> Result<SigningPackage<C>, Box<dyn std::error::Error>> {
    let signing_package = SigningPackage::new(commitments, &args.messages[0]);
    if args.cli {
        print_signing_package(logger, &signing_package);
    }
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
