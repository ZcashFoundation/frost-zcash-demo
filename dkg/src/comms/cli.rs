//! Command line interface implementation of the Comms trait.

use eyre::OptionExt;
use frost_core::keys::dkg::round2;
use frost_core::{self as frost, keys::dkg::round1};

use frost_core::Ciphersuite;

use async_trait::async_trait;

use frost::{keys::PublicKeyPackage, Identifier};

use tokio::io::AsyncBufReadExt as BufReadExt;
use tokio::io::AsyncWriteExt as WriteExt;
use tokio::io::{AsyncBufRead as BufRead, AsyncWrite as Write};

use std::collections::HashMap;
use std::{collections::BTreeMap, error::Error, marker::PhantomData};

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

#[async_trait]
impl<C> Comms<C> for CLIComms<C>
where
    C: Ciphersuite + 'static,
{
    async fn get_identifier(
        &mut self,
        _input: &mut (dyn BufRead + Send + Sync + Unpin),
        _output: &mut (dyn Write + Send + Sync + Unpin),
    ) -> Result<(Identifier<C>, u16), Box<dyn Error>> {
        Ok((
            self.args
                .identifier
                .ok_or_eyre("identifier must be specified")?,
            0,
        ))
    }

    async fn get_round1_packages(
        &mut self,
        mut input: &mut (dyn BufRead + Send + Sync + Unpin),
        output: &mut (dyn Write + Send + Sync + Unpin),
        round1_package: round1::Package<C>,
    ) -> Result<BTreeMap<Identifier<C>, round1::Package<C>>, Box<dyn Error>> {
        let max_signers = self
            .args
            .max_signers
            .ok_or_eyre("max_signers must be specified")?;
        output
            .write_all(b"\n=== ROUND 1: SEND PACKAGES ===\n\n")
            .await?;
        output
            .write_all(
                format!(
                "Round 1 Package to send to all other participants (your identifier: {}):\n\n{}\n\n",
                serde_json::to_string(
                    &self
                        .args
                        .identifier
                        .ok_or_eyre("identifier must be specified")?
                )?,
                serde_json::to_string(&round1_package)?
                )
                .as_bytes(),
            )
            .await?;
        output
            .write_all(b"=== ROUND 1: RECEIVE PACKAGES ===\n\n")
            .await?;
        output
            .write_all(
                format!(
                    "Input Round 1 Packages from the other {} participants.\n\n",
                    max_signers - 1,
                )
                .as_bytes(),
            )
            .await?;
        let mut received_round1_packages = BTreeMap::new();
        for _ in 0..max_signers - 1 {
            let (identifier, round1_package) = read_round1_package(&mut input, output).await?;
            received_round1_packages.insert(identifier, round1_package);
            output.write_all("\n".to_string().as_bytes()).await?;
        }
        Ok(received_round1_packages)
    }

    async fn get_round2_packages(
        &mut self,
        mut input: &mut (dyn BufRead + Send + Sync + Unpin),
        output: &mut (dyn Write + Send + Sync + Unpin),
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    ) -> Result<BTreeMap<Identifier<C>, round2::Package<C>>, Box<dyn Error>> {
        let max_signers = self
            .args
            .max_signers
            .ok_or_eyre("max_signers must be specified")?;
        output
            .write_all(b"=== ROUND 2: SEND PACKAGES ===\n\n")
            .await?;
        for (identifier, package) in round2_packages {
            output
                .write_all(
                    format!(
                        "Round 2 Package to send to participant {} (your identifier: {}):\n\n{}\n\n",
                        serde_json::to_string(&identifier)?,
                        serde_json::to_string(
                            &self
                                .args
                                .identifier
                                .ok_or_eyre("identifier must be specified")?
                        )?,
                        serde_json::to_string(&package)?
                    )
                    .as_bytes(),
                )
                .await?;
        }
        output
            .write_all(b"=== ROUND 2: RECEIVE PACKAGES ===\n\n")
            .await?;
        output
            .write_all(
                format!(
                    "Input Round 2 Packages from the other {} participants.\n\n",
                    max_signers - 1,
                )
                .as_bytes(),
            )
            .await?;
        let mut received_round2_packages = BTreeMap::new();
        for _ in 0..max_signers - 1 {
            let (identifier, round2_package) = read_round2_package(&mut input, output).await?;
            received_round2_packages.insert(identifier, round2_package);
            output.write_all("\n".to_string().as_bytes()).await?;
        }
        output.write_all(b"=== DKG FINISHED ===\n").await?;
        Ok(received_round2_packages)
    }

    fn get_pubkey_identifier_map(&self) -> Result<HashMap<Vec<u8>, Identifier<C>>, Box<dyn Error>> {
        Ok(Default::default())
    }
}

pub async fn read_identifier<C: Ciphersuite + 'static>(
    input: &mut (dyn BufRead + Send + Sync + Unpin),
) -> Result<Identifier<C>, Box<dyn Error>> {
    let mut identifier_input = String::new();
    input.read_line(&mut identifier_input).await?;
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
