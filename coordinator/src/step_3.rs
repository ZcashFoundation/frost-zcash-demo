#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::{Signature, SigningPackage};

use std::{
    fs,
    io::{BufRead, Write},
};

use crate::{args::Args, comms::Comms, step_1::ParticipantsConfig};

#[cfg(feature = "redpallas")]
pub fn request_randomizer(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    signing_package: &SigningPackage,
) -> Result<frost::round2::Randomizer, Box<dyn std::error::Error>> {
    if args.randomizer.is_empty() {
        let rng = rand::thread_rng();
        return Ok(frost::round2::Randomizer::new(rng, signing_package)?);
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

    Ok(frost::round2::Randomizer::deserialize(
        &randomizer
            .try_into()
            .map_err(|_| frost::Error::MalformedIdentifier)?,
    )?)
}

pub async fn step_3(
    args: &Args,
    comms: &mut dyn Comms,
    input: &mut dyn BufRead,
    logger: &mut dyn Write,
    participants: ParticipantsConfig,
    signing_package: &SigningPackage,
    #[cfg(feature = "redpallas")] randomizer: frost::round2::Randomizer,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let group_signature = request_inputs_signature_shares(
        comms,
        input,
        logger,
        participants,
        signing_package,
        #[cfg(feature = "redpallas")]
        randomizer,
    )
    .await?;
    print_signature(args, logger, group_signature)?;
    Ok(group_signature)
}

// Input required:
// 1. number of signers (TODO: maybe pass this in?)
// 2. signatures for all signers
async fn request_inputs_signature_shares(
    comms: &mut dyn Comms,
    input: &mut dyn BufRead,
    logger: &mut dyn Write,
    participants: ParticipantsConfig,
    signing_package: &SigningPackage,
    #[cfg(feature = "redpallas")] randomizer: frost::round2::Randomizer,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let signatures_list = comms
        .get_signature_shares(
            input,
            logger,
            signing_package,
            #[cfg(feature = "redpallas")]
            randomizer,
        )
        .await?;

    #[cfg(feature = "redpallas")]
    let randomizer_params = frost::RandomizedParams::from_randomizer(
        participants.pub_key_package.verifying_key(),
        randomizer,
    );

    let group_signature = frost::aggregate(
        signing_package,
        &signatures_list,
        &participants.pub_key_package,
        #[cfg(feature = "redpallas")]
        &randomizer_params,
    )
    .unwrap();

    Ok(group_signature)
}

fn print_signature(
    args: &Args,
    logger: &mut dyn Write,
    group_signature: Signature,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.signature.is_empty() {
        writeln!(
            logger,
            "Group signature: {}",
            serde_json::to_string(&group_signature)?
        )?;
    } else {
        fs::write(&args.signature, group_signature.serialize())?;
        eprintln!("Raw signature written to {}", &args.signature);
    };
    Ok(())
}
