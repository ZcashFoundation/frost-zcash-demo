use frost_core::{self as frost, Ciphersuite};

use frost::{Signature, SigningPackage};
use frost_rerandomized::{RandomizedCiphersuite, Randomizer};
use rand::thread_rng;
use reddsa::frost::redpallas::PallasBlake2b512;

use std::{
    fs,
    io::{BufRead, Write},
};

use crate::{args::ProcessedArgs, comms::Comms, step_1::ParticipantsConfig};

pub async fn step_3<C: RandomizedCiphersuite + 'static>(
    args: &ProcessedArgs<C>,
    comms: &mut dyn Comms<C>,
    input: &mut dyn BufRead,
    logger: &mut dyn Write,
    participants: ParticipantsConfig<C>,
    signing_package: &SigningPackage<C>,
) -> Result<Signature<C>, Box<dyn std::error::Error>> {
    let group_signature =
        request_inputs_signature_shares(args, comms, input, logger, participants, signing_package)
            .await?;
    print_signature(args, logger, group_signature)?;
    Ok(group_signature)
}

// Input required:
// 1. number of signers (TODO: maybe pass this in?)
// 2. signatures for all signers
async fn request_inputs_signature_shares<C: RandomizedCiphersuite + 'static>(
    args: &ProcessedArgs<C>,
    comms: &mut dyn Comms<C>,
    input: &mut dyn BufRead,
    logger: &mut dyn Write,
    participants: ParticipantsConfig<C>,
    signing_package: &SigningPackage<C>,
) -> Result<Signature<C>, Box<dyn std::error::Error>> {
    // TODO: support multiple
    let randomizer = if args.randomizers.is_empty() && C::ID == PallasBlake2b512::ID {
        let rng = thread_rng();
        Some(Randomizer::new(rng, signing_package)?)
    } else if args.randomizers.is_empty() {
        None
    } else {
        Some(args.randomizers[0])
    };

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
    args: &ProcessedArgs<C>,
    logger: &mut dyn Write,
    group_signature: Signature<C>,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.signature.is_empty() {
        writeln!(
            logger,
            "Signature:\n{}",
            hex::encode(&group_signature.serialize()?)
        )?;
    } else {
        fs::write(&args.signature, group_signature.serialize()?)?;
        eprintln!("Raw signature written to {}", &args.signature);
    };
    Ok(())
}
