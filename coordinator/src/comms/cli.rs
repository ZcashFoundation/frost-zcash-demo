//! Command line interface implementation of the Comms trait.

#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use eyre::eyre;

use async_trait::async_trait;

use frost::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
    SigningPackage,
};

use std::{
    collections::BTreeMap,
    error::Error,
    io::{BufRead, Write},
};

use super::Comms;

pub struct CLIComms {}

#[async_trait(?Send)]
impl Comms for CLIComms {
    async fn get_signing_commitments(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        pub_key_package: &PublicKeyPackage,
        num_of_participants: u16,
    ) -> Result<BTreeMap<Identifier, SigningCommitments>, Box<dyn Error>> {
        let mut participants_list = Vec::new();
        let mut commitments_list: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

        for i in 1..=num_of_participants {
            writeln!(output, "Identifier for participant {:?} (hex encoded): ", i)?;
            let id_value = read_identifier(input)?;
            validate(id_value, pub_key_package, &participants_list)?;
            participants_list.push(id_value);

            writeln!(
                output,
                "Please enter JSON encoded commitments for participant {}:",
                hex::encode(id_value.serialize())
            )?;
            let mut commitments_input = String::new();
            input.read_line(&mut commitments_input)?;
            let commitments = serde_json::from_str(&commitments_input)?;
            commitments_list.insert(id_value, commitments);
        }

        Ok(commitments_list)
    }

    async fn get_signature_shares(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        signing_package: &SigningPackage,
        #[cfg(feature = "redpallas")] _randomizer: frost::round2::Randomizer,
    ) -> Result<BTreeMap<Identifier, SignatureShare>, Box<dyn Error>> {
        let mut signatures_list: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
        for p in signing_package.signing_commitments().keys() {
            writeln!(
                output,
                "Please enter JSON encoded signature shares for participant {}:",
                hex::encode(p.serialize())
            )?;

            let mut signature_input = String::new();
            input.read_line(&mut signature_input)?;
            let signatures = serde_json::from_str(&signature_input)?;
            signatures_list.insert(*p, signatures);
        }
        Ok(signatures_list)
    }
}

pub fn read_identifier(input: &mut dyn BufRead) -> Result<Identifier, Box<dyn Error>> {
    let mut identifier_input = String::new();
    input.read_line(&mut identifier_input)?;
    let bytes = hex::decode(identifier_input.trim())?;
    let serialization = bytes.try_into().map_err(|_| eyre!("Invalid Identifier"))?;
    let identifier = Identifier::deserialize(&serialization)?;
    Ok(identifier)
}

pub fn validate(
    id: Identifier,
    key_package: &PublicKeyPackage,
    id_list: &[Identifier],
) -> Result<(), frost::Error> {
    if !key_package.verifying_shares().contains_key(&id) {
        return Err(frost::Error::MalformedIdentifier);
    }; // TODO: Error is actually that the identifier does not exist
    if id_list.contains(&id) {
        return Err(frost::Error::DuplicatedIdentifier);
    };
    Ok(())
}
