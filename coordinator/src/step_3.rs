#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::{round2::SignatureShare, Identifier, Signature, SigningPackage};

use std::{
    collections::HashMap,
    io::{BufRead, Write},
};

use crate::step_1::ParticipantsConfig;

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

pub fn step_3(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    participants: ParticipantsConfig,
    signing_package: SigningPackage,
    #[cfg(feature = "redpallas")] randomizer: frost::round2::Randomizer,
) -> Signature {
    let group_signature = request_inputs_signature_shares(
        input,
        logger,
        participants,
        signing_package,
        #[cfg(feature = "redpallas")]
        randomizer,
    )
    .unwrap();
    print_signature(logger, group_signature);
    group_signature
}

// Input required:
// 1. number of signers (TODO: maybe pass this in?)
// 2. signatures for all signers
fn request_inputs_signature_shares(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
    participants: ParticipantsConfig,
    signing_package: SigningPackage,
    #[cfg(feature = "redpallas")] randomizer: frost::round2::Randomizer,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let mut signatures_list: HashMap<Identifier, SignatureShare> = HashMap::new();

    for p in participants.participants {
        writeln!(
            logger,
            "Please enter JSON encoded signature shares for participant {}:",
            hex::encode(p.serialize())
        )
        .unwrap();

        let mut signature_input = String::new();
        input.read_line(&mut signature_input)?;
        let signatures = serde_json::from_str(&signature_input)?;
        signatures_list.insert(p, signatures);
    }

    #[cfg(feature = "redpallas")]
    let randomizer_params = frost::RandomizedParams::from_randomizer(
        participants.pub_key_package.group_public(),
        randomizer,
    );

    let group_signature = frost::aggregate(
        &signing_package,
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
