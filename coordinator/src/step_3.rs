#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::{Signature, SigningPackage};

use std::{
    collections::HashMap,
    io::{BufRead, Write},
};

use crate::{comms::Comms, step_1::ParticipantsConfig};

#[cfg(feature = "redpallas")]
pub fn request_randomizer(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
) -> Result<frost::round2::Randomizer, Box<dyn std::error::Error>> {
    writeln!(logger, "Enter the randomizer (hex string):")?;

    let mut randomizer = String::new();
    input.read_line(&mut randomizer)?;

    Ok(frost::round2::Randomizer::deserialize(
        &hex::decode(randomizer.trim())?
            .try_into()
            .map_err(|_| frost::Error::MalformedIdentifier)?,
    )?)
}

pub(crate) async fn step_3(
    comms: &mut impl Comms,
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
    print_signature(logger, group_signature);
    Ok(group_signature)
}

// Input required:
// 1. number of signers (TODO: maybe pass this in?)
// 2. signatures for all signers
async fn request_inputs_signature_shares(
    comms: &mut impl Comms,
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
        participants.pub_key_package.group_public(),
        randomizer,
    );

    let signatures_list: HashMap<_, _> = signatures_list.into_iter().collect();

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

fn print_signature(logger: &mut dyn Write, group_signature: Signature) {
    writeln!(
        logger,
        "Group signature: {}",
        serde_json::to_string(&group_signature).unwrap()
    )
    .unwrap();
}
