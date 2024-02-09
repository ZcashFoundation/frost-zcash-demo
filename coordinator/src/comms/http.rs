//! HTTP implementation of the Comms trait.

use async_trait::async_trait;
#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use eyre::eyre;
use message_io::{
    network::{Endpoint, NetEvent, Transport},
    node::{self, NodeHandler, NodeListener},
};
use tokio::sync::mpsc::{self, Receiver, Sender};

use frost::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
    SigningPackage,
};

use std::{
    collections::BTreeMap,
    error::Error,
    io::{BufRead, Write},
};

use super::{Comms, Message};
use crate::args::Args;

pub struct HTTPComms {
    client: reqwest::Client,
    host_port: String,
}

impl HTTPComms {
    pub fn new(args: &Args) -> Self {
        let client = reqwest::Client::new();
        let http_comm = Self {
            client,
            host_port: format!("{}:{}"),
        };
        http_comm
    }
}

#[async_trait(?Send)]
impl Comms for HTTPComms {
    async fn get_signing_commitments(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        _pub_key_package: &PublicKeyPackage,
        num_of_participants: u16,
    ) -> Result<BTreeMap<Identifier, SigningCommitments>, Box<dyn Error>> {
        let r = self
            .client
            .post(format!("{}/create_new_session", self.host_port))
            .json(&server::CreateNewSessionArgs {
                identifiers: key_packages.keys().copied().collect::<Vec<_>>(),
                message_count: 1,
            })
            .send()
            .await?
            .json::<server::CreateNewSessionOutput>()
            .await?;

        let mut signing_commitments = BTreeMap::new();
        eprintln!("Waiting for participants to send their commitments...");
        for _ in 0..num_of_participants {
            let (endpoint, data) = self
                .input_rx
                .recv()
                .await
                .ok_or(eyre!("Did not receive all commitments"))?;
            let message: Message = serde_json::from_slice(&data)?;
            if let Message::IdentifiedCommitments {
                identifier,
                commitments,
            } = message
            {
                self.endpoints.insert(identifier, endpoint);
                signing_commitments.insert(identifier, commitments);
            } else {
                Err(eyre!("Expected IdentifiedCommitments message"))?;
            }
        }
        Ok(signing_commitments)
    }

    async fn get_signature_shares(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        signing_package: &SigningPackage,
        #[cfg(feature = "redpallas")] randomizer: frost::round2::Randomizer,
    ) -> Result<BTreeMap<Identifier, SignatureShare>, Box<dyn Error>> {
        // Send SigningPackage to all participants
        eprintln!("Sending SigningPackage to participants...");

        #[cfg(not(feature = "redpallas"))]
        let data = serde_json::to_vec(&Message::SigningPackage(signing_package.clone()))?;
        #[cfg(feature = "redpallas")]
        let data = serde_json::to_vec(&Message::SigningPackageAndRandomizer {
            signing_package: signing_package.clone(),
            randomizer,
        })?;

        for identifier in signing_package.signing_commitments().keys() {
            let endpoint = self
                .endpoints
                .get(identifier)
                .ok_or(eyre!("unknown identifier"))?;
            self.handler.network().send(*endpoint, &data);
        }

        eprintln!("Waiting for participants to send their SignatureShares...");
        // Read SignatureShare from all participants
        let mut signature_shares = BTreeMap::new();
        for _ in 0..signing_package.signing_commitments().len() {
            let (endpoint, data) = self
                .input_rx
                .recv()
                .await
                .ok_or(eyre!("Did not receive all commitments"))?;
            let message: Message = serde_json::from_slice(&data)?;
            if let Message::SignatureShare(signature_share) = message {
                let identifier = self
                    .endpoints
                    .iter()
                    .find_map(|(i, e)| if *e == endpoint { Some(i) } else { None })
                    .ok_or(eyre!("Unknown participant"))?;
                signature_shares.insert(*identifier, signature_share);
            } else {
                Err(eyre!("Expected IdentifiedCommitments message"))?;
            }
        }
        Ok(signature_shares)
    }
}
