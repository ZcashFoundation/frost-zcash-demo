//! Command line interface implementation of the Comms trait.

use async_trait::async_trait;
#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use eyre::eyre;

use frost::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
    SigningPackage,
};

use std::{
    error::Error,
    io::{BufRead, Write},
};

use crate::comms::Comms;

use super::GenericSigningPackage;
// use super::Comms;

pub struct CLIComms {}

#[async_trait(?Send)]
impl Comms for CLIComms {
    async fn get_signing_package(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        _commitments: SigningCommitments,
        _identifier: Identifier,
    ) -> Result<GenericSigningPackage, Box<dyn Error>> {
        writeln!(output, "Enter the JSON-encoded SigningPackage:")?;

        let mut signing_package_json = String::new();

        input.read_line(&mut signing_package_json)?;

        // TODO: change to return a generic Error and use a better error
        let signing_package: SigningPackage = serde_json::from_str(signing_package_json.trim())?;

        #[cfg(feature = "redpallas")]
        {
            writeln!(output, "Enter the randomizer (hex string):")?;

            let mut json = String::new();
            input.read_line(&mut json).unwrap();

            let randomizer = frost::round2::Randomizer::deserialize(
                &hex::decode(json.trim())?
                    .try_into()
                    .map_err(|_| eyre!("Invalid randomizer"))?,
            )?;
            Ok((signing_package, randomizer))
        }

        #[cfg(not(feature = "redpallas"))]
        Ok(signing_package)
    }

    async fn send_signature_share(
        &mut self,
        _signature_share: SignatureShare,
    ) -> Result<(), Box<dyn Error>> {
        Ok(())
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
