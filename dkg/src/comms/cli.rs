//! Command line interface implementation of the Comms trait.

use eyre::OptionExt;
use frost_core::keys::dkg::round2;
use frost_core::{self as frost, keys::dkg::round1};

use frost_core::Ciphersuite;

use async_trait::async_trait;

use frost::{keys::PublicKeyPackage, Identifier};
use frostd::PublicKey;

use std::collections::HashMap;
use std::{
    collections::BTreeMap,
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
};

use crate::args::ProcessedArgs;
use crate::inputs::{read_round1_package, read_round2_package};

use super::Comms;

pub struct CLIComms<C: Ciphersuite> {
    args: ProcessedArgs<C>,
    _phantom: PhantomData<C>,
}

impl<C> CLIComms<C>
where
    C: Ciphersuite,
{
    pub fn new(args: &ProcessedArgs<C>) -> Self {
        Self {
            args: args.clone(),
            _phantom: Default::default(),
        }
    }
}

#[async_trait(?Send)]
impl<C> Comms<C> for CLIComms<C>
where
    C: Ciphersuite + 'static,
{
    async fn get_identifier_and_max_signers(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
    ) -> Result<(Identifier<C>, u16), Box<dyn Error>> {
        Ok((
            self.args
                .identifier
                .ok_or_eyre("identifier must be specified")?,
            self.args
                .max_signers
                .ok_or_eyre("max_signers must be specified")?,
        ))
    }

    async fn get_round1_packages(
        &mut self,
        mut input: &mut dyn BufRead,
        output: &mut dyn Write,
        round1_package: round1::Package<C>,
    ) -> Result<BTreeMap<Identifier<C>, round1::Package<C>>, Box<dyn Error>> {
        let max_signers = self
            .args
            .max_signers
            .ok_or_eyre("max_signers must be specified")?;
        writeln!(output, "\n=== ROUND 1: SEND PACKAGES ===\n")?;
        writeln!(
            output,
            "Round 1 Package to send to all other participants (your identifier: {}):\n\n{}\n",
            serde_json::to_string(
                &self
                    .args
                    .identifier
                    .ok_or_eyre("identifier must be specified")?
            )?,
            serde_json::to_string(&round1_package)?
        )?;
        writeln!(output, "=== ROUND 1: RECEIVE PACKAGES ===\n")?;
        writeln!(
            output,
            "Input Round 1 Packages from the other {} participants.\n",
            max_signers - 1,
        )?;
        let mut received_round1_packages = BTreeMap::new();
        for _ in 0..max_signers - 1 {
            let (identifier, round1_package) = read_round1_package(&mut input, output)?;
            received_round1_packages.insert(identifier, round1_package);
            writeln!(output)?;
        }
        Ok(received_round1_packages)
    }

    async fn get_round2_packages(
        &mut self,
        mut input: &mut dyn BufRead,
        output: &mut dyn Write,
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    ) -> Result<BTreeMap<Identifier<C>, round2::Package<C>>, Box<dyn Error>> {
        let max_signers = self
            .args
            .max_signers
            .ok_or_eyre("max_signers must be specified")?;
        writeln!(output, "=== ROUND 2: SEND PACKAGES ===\n")?;
        for (identifier, package) in round2_packages {
            writeln!(
                output,
                "Round 2 Package to send to participant {} (your identifier: {}):\n\n{}\n",
                serde_json::to_string(&identifier)?,
                serde_json::to_string(
                    &self
                        .args
                        .identifier
                        .ok_or_eyre("identifier must be specified")?
                )?,
                serde_json::to_string(&package)?
            )?;
        }
        writeln!(output, "=== ROUND 2: RECEIVE PACKAGES ===\n")?;
        writeln!(
            output,
            "Input Round 2 Packages from the other {} participants.\n",
            max_signers - 1,
        )?;
        let mut received_round2_packages = BTreeMap::new();
        for _ in 0..max_signers - 1 {
            let (identifier, round2_package) = read_round2_package(&mut input, output)?;
            received_round2_packages.insert(identifier, round2_package);
            writeln!(output)?;
        }
        writeln!(output, "=== DKG FINISHED ===")?;
        Ok(received_round2_packages)
    }

    fn get_pubkey_identifier_map(
        &self,
    ) -> Result<HashMap<PublicKey, Identifier<C>>, Box<dyn Error>> {
        Ok(Default::default())
    }
}

pub fn read_identifier<C: Ciphersuite + 'static>(
    input: &mut dyn BufRead,
) -> Result<Identifier<C>, Box<dyn Error>> {
    let mut identifier_input = String::new();
    input.read_line(&mut identifier_input)?;
    let bytes = hex::decode(identifier_input.trim())?;
    let identifier = Identifier::<C>::deserialize(&bytes)?;
    Ok(identifier)
}

pub fn validate<C: Ciphersuite>(
    id: Identifier<C>,
    key_package: &PublicKeyPackage<C>,
    id_list: &[Identifier<C>],
) -> Result<(), frost::Error<C>> {
    if !key_package.verifying_shares().contains_key(&id) {
        return Err(frost::Error::MalformedIdentifier);
    }; // TODO: Error is actually that the identifier does not exist
    if id_list.contains(&id) {
        return Err(frost::Error::DuplicatedIdentifier);
    };
    Ok(())
}
