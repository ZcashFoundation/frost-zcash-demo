#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::{keys::PublicKeyPackage, round1::SigningCommitments, Identifier};

use std::{
    collections::BTreeMap,
    io::{BufRead, Write},
};

use crate::{args::Args, comms::Comms, input::read_from_file_or_stdin};

#[derive(PartialEq, Debug)]
pub struct ParticipantsConfig {
    pub commitments: BTreeMap<Identifier, SigningCommitments>,
    pub pub_key_package: PublicKeyPackage,
}

// TODO: needs to include the coordinator's keys!
pub async fn step_1(
    args: &Args,
    comms: &mut dyn Comms,
    reader: &mut dyn BufRead,
    logger: &mut dyn Write,
) -> Result<ParticipantsConfig, Box<dyn std::error::Error>> {
    let participants = read_commitments(args, comms, reader, logger).await?;
    print_participants(logger, &participants.commitments);
    Ok(participants)
}

// TODO: validate min num of participants

// Input required:
// 1. public key package
// 2. number of participants
// 3. identifiers for all participants
async fn read_commitments(
    args: &Args,
    comms: &mut dyn Comms,
    input: &mut dyn BufRead,
    logger: &mut dyn Write,
) -> Result<ParticipantsConfig, Box<dyn std::error::Error>> {
    let pub_key_package = read_from_file_or_stdin(
        input,
        logger,
        "public key package",
        &args.public_key_package,
    )?;
    let pub_key_package: PublicKeyPackage = serde_json::from_str(&pub_key_package)?;

    let num_of_participants = if args.cli && args.num_signers == 0 {
        writeln!(logger, "The number of participants: ")?;

        let mut participants = String::new();
        input.read_line(&mut participants)?;
        participants.trim().parse::<u16>()?
    } else {
        args.num_signers
    };

    let commitments_list = comms
        .get_signing_commitments(input, logger, &pub_key_package, num_of_participants)
        .await?;

    Ok(ParticipantsConfig {
        commitments: commitments_list,
        pub_key_package,
    })
}

pub fn print_participants(
    logger: &mut dyn Write,
    participants: &BTreeMap<Identifier, SigningCommitments>,
) {
    writeln!(logger, "Selected participants: ",).unwrap();

    for p in participants.keys() {
        writeln!(logger, "{}", serde_json::to_string(p).unwrap()).unwrap();
    }
}

#[cfg(all(test, not(feature = "redpallas")))]
mod tests {
    use std::collections::BTreeMap;

    use frost::{
        keys::{PublicKeyPackage, VerifyingShare},
        Error, Identifier, VerifyingKey,
    };
    use frost_ed25519 as frost;
    use hex::FromHex;

    use crate::comms::cli::validate;

    const PUBLIC_KEY_1: &str = "fc2c9b8e335c132d9ebe0403c9317aac480bbbf8cbdb1bc3730bb68eb60dadf9";
    const PUBLIC_KEY_2: &str = "2cff4148a2f965801fb1f25f1d2a4e5df2f75b3a57cd06f30471c2c774419a41";
    const GROUP_PUBLIC_KEY: &str =
        "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";

    fn build_pub_key_package() -> PublicKeyPackage {
        let id_1 = Identifier::try_from(1).unwrap();
        let id_2 = Identifier::try_from(2).unwrap();

        let mut signer_pubkeys = BTreeMap::new();
        signer_pubkeys.insert(
            id_1,
            VerifyingShare::deserialize(<[u8; 32]>::from_hex(PUBLIC_KEY_1).unwrap()).unwrap(),
        );
        signer_pubkeys.insert(
            id_2,
            VerifyingShare::deserialize(<[u8; 32]>::from_hex(PUBLIC_KEY_2).unwrap()).unwrap(),
        );

        let group_public =
            VerifyingKey::deserialize(<[u8; 32]>::from_hex(GROUP_PUBLIC_KEY).unwrap()).unwrap();

        PublicKeyPackage::new(signer_pubkeys, group_public)
    }

    #[test]
    fn check_validate() {
        let id_1 = Identifier::try_from(1).unwrap();
        let id_2 = Identifier::try_from(2).unwrap();

        let id_list = [id_1];
        let key_package = build_pub_key_package();

        let validated = validate(id_2, &key_package, &id_list);

        assert!(validated.is_ok())
    }

    #[test]
    fn check_validation_errors_for_missing_identifiers() {
        let id_1 = Identifier::try_from(1).unwrap();
        let id_2 = Identifier::try_from(2).unwrap();
        let id_3 = Identifier::try_from(3).unwrap();

        let id_list = [id_1, id_2];
        let key_package = build_pub_key_package();

        let validated = validate(id_3, &key_package, &id_list);
        assert!(validated.is_err());
        assert!(validated == Err(Error::MalformedIdentifier))
    }

    #[test]
    fn check_validation_errors_for_duplicate_identifiers() {
        let id_1 = Identifier::try_from(1).unwrap();
        let id_2 = Identifier::try_from(2).unwrap();

        let id_list = [id_1, id_2];
        let key_package = build_pub_key_package();

        let validated = validate(id_1, &key_package, &id_list);
        assert!(validated.is_err());
        assert!(validated == Err(Error::DuplicatedIdentifier))
    }
}
