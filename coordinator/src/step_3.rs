use frost_core::{self as frost, Ciphersuite};

use frost::{Signature, SigningPackage};
use frost_rerandomized::RandomizedCiphersuite;

use std::{
    fs,
    io::{BufRead, Write},
};

use crate::{args::Args, comms::Comms, step_1::ParticipantsConfig};

pub fn request_randomizer<C: RandomizedCiphersuite + 'static>(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    signing_package: &SigningPackage<C>,
) -> Result<frost_rerandomized::Randomizer<C>, Box<dyn std::error::Error>> {
    if args.randomizer.is_empty() {
        let rng = rand::thread_rng();
        return Ok(frost_rerandomized::Randomizer::new(rng, signing_package)?);
    };
    let randomizer = if args.randomizer == "-" {
        writeln!(logger, "Enter the randomizer (hex string):")?;

        let mut randomizer = String::new();
        input.read_line(&mut randomizer)?;

        hex::decode(randomizer.trim())?
    } else {
        eprintln!("Reading randomizer from {}...", &args.randomizer);
        fs::read(&args.randomizer)?
    };

    Ok(frost_rerandomized::Randomizer::deserialize(&randomizer)?)
}

pub async fn step_3<C: Ciphersuite + 'static>(
    args: &Args,
    comms: &mut dyn Comms<C>,
    input: &mut dyn BufRead,
    logger: &mut dyn Write,
    participants: ParticipantsConfig<C>,
    signing_package: &SigningPackage<C>,
    randomizer: Option<frost_rerandomized::Randomizer<C>>,
) -> Result<Signature<C>, Box<dyn std::error::Error>> {
    let group_signature = request_inputs_signature_shares(
        comms,
        input,
        logger,
        participants,
        signing_package,
        randomizer,
    )
    .await?;
    print_signature(args, logger, group_signature)?;
    Ok(group_signature)
}

// Input required:
// 1. number of signers (TODO: maybe pass this in?)
// 2. signatures for all signers
async fn request_inputs_signature_shares<C: Ciphersuite>(
    comms: &mut dyn Comms<C>,
    input: &mut dyn BufRead,
    logger: &mut dyn Write,
    participants: ParticipantsConfig<C>,
    signing_package: &SigningPackage<C>,
    randomizer: Option<frost_rerandomized::Randomizer<C>>,
) -> Result<Signature<C>, Box<dyn std::error::Error>> {
    let signatures_list = comms
        .get_signature_shares(input, logger, signing_package, randomizer)
        .await?;

    let group_signature = if let Some(randomizer) = randomizer {
        let randomizer_params = frost_rerandomized::RandomizedParams::<C>::from_randomizer(
            participants.pub_key_package.verifying_key(),
            randomizer,
        );

        frost_rerandomized::aggregate(
            signing_package,
            &signatures_list,
            &participants.pub_key_package,
            &randomizer_params,
        )
        .unwrap()
    } else {
        frost::aggregate::<C>(
            signing_package,
            &signatures_list,
            &participants.pub_key_package,
        )
        .unwrap()
    };

    Ok(group_signature)
}

fn print_signature<C: Ciphersuite + 'static>(
    args: &Args,
    logger: &mut dyn Write,
    group_signature: Signature<C>,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.signature.is_empty() {
        writeln!(
            logger,
            "Group signature: {}",
            serde_json::to_string(&group_signature)?
        )?;
    } else {
        fs::write(&args.signature, group_signature.serialize()?)?;
        eprintln!("Raw signature written to {}", &args.signature);
    };
    Ok(())
}
