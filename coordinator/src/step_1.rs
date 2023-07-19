use frost_ed25519 as frost;

use frost::{keys::PublicKeyPackage, Error, Identifier};

use std::io::{BufRead, Write};

pub struct ParticipantsConfig {
    pub participants: Vec<Identifier>,
    pub pub_key_package: PublicKeyPackage,
}

// TODO: needs to include the coordinator's keys!
pub fn step_1(reader: &mut impl BufRead, logger: &mut dyn Write) -> ParticipantsConfig {
    let participants = choose_participants(reader, logger).unwrap();
    print_participants(logger, &participants.participants);
    participants
}

fn validate(
    id: Identifier,
    key_package: PublicKeyPackage,
    id_list: &[Identifier],
) -> Result<(), Error> {
    if key_package.signer_pubkeys().contains_key(&id) {
        return Err(Error::DuplicatedIdentifier);
    }; // TODO: Error is actually that the identifier does not exist
    if !id_list.contains(&id) {
        return Err(Error::DuplicatedIdentifier);
    };
    Ok(())
}

// TODO: validate min num of participants
// TODO: validate participant must exist

// Input required:
// 1. public key package
// 2. number of participants
// 3. identifiers for all participants
fn choose_participants(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
) -> Result<ParticipantsConfig, Error> {
    writeln!(logger, "Paste the JSON public key package: ").unwrap();
    let mut key_package = String::new();
    input.read_line(&mut key_package).unwrap();
    let pub_key_package: PublicKeyPackage = serde_json::from_str(&key_package).unwrap();

    writeln!(logger, "The number of participants: ").unwrap();

    let mut participants = String::new();
    input.read_line(&mut participants).unwrap();
    let num_of_participants = participants.trim().parse::<u16>().unwrap();

    let mut participants = Vec::new();

    for i in 1..=num_of_participants {
        let package = pub_key_package.clone();
        writeln!(logger, "Identifier for participant {:?} (hex encoded):", i).unwrap();

        let mut identifier_input = String::new();

        input.read_line(&mut identifier_input).unwrap();

        let id_value = serde_json::from_str(&identifier_input).unwrap();

        validate(id_value, package, &participants)?;

        participants.push(id_value)
    }
    Ok(ParticipantsConfig {
        participants,
        pub_key_package,
    })
}

pub fn print_participants(logger: &mut dyn Write, participants: &Vec<Identifier>) {
    writeln!(logger, "Selected participants:",).unwrap();

    for p in participants {
        writeln!(logger, "{}", serde_json::to_string(p).unwrap()).unwrap();
    }
}
