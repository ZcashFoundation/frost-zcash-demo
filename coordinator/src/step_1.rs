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

// TODO: validate min num of participants
// TODO: validate participant must exist

// Input required:
// 1. public key package
// 2. number of signparticipantsers
// 3. identifiers for all signers
fn choose_participants(
    input: &mut impl BufRead,
    logger: &mut dyn Write,
) -> Result<ParticipantsConfig, Error> {
    writeln!(logger, "Paste the JSON public key package: ").unwrap();
    let mut key_package = String::new();
    input.read_line(&mut key_package).unwrap();
    let pub_key_package = serde_json::from_str(&key_package).unwrap();

    //TODO: validate for unique identifiers
    writeln!(logger, "The number of participants: ").unwrap();

    let mut signers = String::new();
    input.read_line(&mut signers).unwrap();
    let num_of_signers = signers.trim().parse::<u16>().unwrap();

    let mut participants = Vec::new();

    for i in 1..=num_of_signers {
        writeln!(logger, "Identifier for participant {:?} (hex encoded):", i).unwrap();

        let mut identifier_input = String::new();

        input.read_line(&mut identifier_input).unwrap();

        let id_value = serde_json::from_str(&identifier_input).unwrap();
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
