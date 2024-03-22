//! HTTP implementation of the Comms trait.

use async_trait::async_trait;

#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use eyre::eyre;
use server::Uuid;

use frost::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
    SigningPackage,
};

use std::{
    collections::BTreeMap,
    error::Error,
    io::{BufRead, Write},
    time::Duration,
};

use super::Comms;
use crate::args::Args;

pub struct HTTPComms {
    client: reqwest::Client,
    host_port: String,
    session_id: Option<Uuid>,
}

impl HTTPComms {
    pub fn new(args: &Args) -> Self {
        let client = reqwest::Client::new();
        Self {
            client,
            host_port: format!("http://{}:{}", args.ip, args.port),
            session_id: None,
        }
    }
}

#[async_trait(?Send)]
impl Comms for HTTPComms {
    async fn get_signing_commitments(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        _pub_key_package: &PublicKeyPackage,
        num_signers: u16,
    ) -> Result<BTreeMap<Identifier, SigningCommitments>, Box<dyn Error>> {
        let r = self
            .client
            .post(format!("{}/create_new_session", self.host_port))
            .json(&server::CreateNewSessionArgs {
                num_signers,
                message_count: 1,
            })
            .send()
            .await?
            .json::<server::CreateNewSessionOutput>()
            .await?;

        eprintln!(
            "Send the following session ID to participants: {}",
            r.session_id
        );
        self.session_id = Some(r.session_id);
        eprint!("Waiting for participants to send their commitments...");

        let r = loop {
            let r = self
                .client
                .post(format!("{}/get_commitments", self.host_port))
                .json(&server::GetCommitmentsArgs {
                    session_id: r.session_id,
                })
                .send()
                .await?;
            if r.status() != 200 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
            } else {
                break r.json::<server::GetCommitmentsOutput>().await?;
            }
        };
        eprintln!();

        Ok(r.commitments
            .first()
            .ok_or(eyre!("empty commitments"))
            .cloned()?)
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

        let _r = self
            .client
            .post(format!("{}/send_signing_package", self.host_port))
            .json(&server::SendSigningPackageArgs {
                aux_msg: Default::default(),
                session_id: self.session_id.unwrap(),
                signing_package: vec![signing_package.clone()],
                #[cfg(feature = "redpallas")]
                randomizer: vec![randomizer],
            })
            .send()
            .await?
            .bytes()
            .await?;

        eprintln!("Waiting for participants to send their SignatureShares...");

        let r = loop {
            let r = self
                .client
                .post(format!("{}/get_signature_shares", self.host_port))
                .json(&server::GetSignatureSharesArgs {
                    session_id: self.session_id.unwrap(),
                })
                .send()
                .await?;
            if r.status() != 200 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
            } else {
                break r.json::<server::GetSignatureSharesOutput>().await?;
            }
        };
        eprintln!();

        Ok(r.signature_shares
            .first()
            .ok_or(eyre!("empty signature shares"))?
            .clone())
    }
}
